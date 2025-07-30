"""Tests for FL-SEC-1 – End-to-end encryption of federated parameters.

RED phase: this test should fail until the encryption layer is implemented.
"""
from __future__ import annotations

import numpy as np
import pytest

# PyTest marker so we can run only security-related FL tests if desired
pytestmark = [pytest.mark.unit, pytest.mark.security]


def test_encrypt_decrypt_roundtrip() -> None:
    """Encrypts a random tensor and ensures decryption returns identical data."""
    # GIVEN random model parameters represented as a numpy array
    data = np.random.rand(16, 16).astype(np.float32)

    # WHEN we encrypt and then decrypt using the SecureFL helper
    from atous_sec_network.core.secure_fl import SecureFL  # local import to avoid hard dep if module missing

    secure_fl = SecureFL()
    ciphertext, nonce, tag, peer_pubkey = secure_fl.encrypt_parameters(data)
    recovered = secure_fl.decrypt_parameters(ciphertext, nonce, tag, peer_pubkey)

    # THEN recovered parameters must match the original within floating-point tolerance
    np.testing.assert_allclose(recovered, data, rtol=1e-5, atol=1e-6)
