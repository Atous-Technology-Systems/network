import json
import pytest
from fastapi.testclient import TestClient

from atous_sec_network.api.server import app
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


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


@pytest.fixture
def client():
    return TestClient(app)


def test_enroll_success_returns_cert_and_chain(client):
    csr_pem = _make_csr("agent-itg-1")
    payload = {
        "device_info": {"os": "Windows", "arch": "x86_64", "hostname": "node-itg-1"},
        "attestation": None,
        "csr_pem": csr_pem,
    }

    resp = client.post("/v1/agents/enroll", json=payload)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "agent_id" in data
    assert "certificate_pem" in data and data["certificate_pem"].startswith("-----BEGIN CERTIFICATE-")
    assert "ca_chain_pem" in data and data["ca_chain_pem"].startswith("-----BEGIN CERTIFICATE-")


def test_enroll_rejects_invalid_csr(client):
    payload = {
        "device_info": {"os": "Windows"},
        "attestation": None,
        "csr_pem": "invalid-csr",
    }
    resp = client.post("/v1/agents/enroll", json=payload)
    assert resp.status_code in (400, 422)


