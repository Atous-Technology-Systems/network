"""Minimal CA service for issuing client certificates from CSR (MVP).

This module intentionally keeps implementation simple and self-contained to
support TDD for the enroll feature. For production, integrate with a proper
CA/key storage and rotation policies.
"""

from __future__ import annotations

from datetime import datetime, timedelta, UTC
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


class CAService:
    """Lightweight in-memory CA for tests and MVP."""

    def __init__(self) -> None:
        # Generate ephemeral CA (MVP). Replace with persisted CA in production
        self._ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ATous-Dev-CA")])
        self._ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(self._ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
            .not_valid_after(datetime.now(UTC) + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(self._ca_key, hashes.SHA256())
        )

    def issue_certificate(self, csr_pem: str) -> Tuple[str, str]:
        """Issue a client certificate for a given CSR PEM.

        Returns (certificate_pem, ca_chain_pem).
        Raises ValueError for invalid CSR.
        """
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            raise ValueError("Invalid CSR") from exc

        # CN: prefer CSR subject CN; fallback to random serial
        try:
            cn_attr = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]
            cn_value = cn_attr.value
        except Exception:  # noqa: BLE001
            cn_value = f"agent-{x509.random_serial_number()}"

        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn_value)])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
            .not_valid_after(datetime.now(UTC) + timedelta(days=90))
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .sign(self._ca_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        ca_pem = self._ca_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        return cert_pem, ca_pem


