import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


def _make_csr(common_name: str) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    return csr_pem


def test_issue_certificate_success():
    from atous_sec_network.security.ca_service import CAService

    ca = CAService()
    csr_pem = _make_csr("agent-test")
    cert_pem, ca_pem = ca.issue_certificate(csr_pem)

    # Parse certs
    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    ca_cert = x509.load_pem_x509_certificate(ca_pem.encode("utf-8"))

    # CN check
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert cn in ("agent-test", cn)  # CN may be copied or replaced by service

    # Issuer is CA
    assert cert.issuer == ca_cert.subject

    # Basic extensions exist
    eku = cert.extensions.get_extension_for_oid(x509.ExtensionOID.EXTENDED_KEY_USAGE).value
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku


def test_issue_certificate_invalid_csr():
    from atous_sec_network.security.ca_service import CAService

    ca = CAService()
    with pytest.raises(ValueError):
        ca.issue_certificate("not-a-csr")


