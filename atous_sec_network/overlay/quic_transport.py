from __future__ import annotations

from typing import Optional


class QuicTransport:
    """Prototype wrapper for a QUIC transport.

    This MVP does not require aioquic. If unavailable, `is_available` is False and
    methods that depend on QUIC will raise NotImplementedError.
    """

    def __init__(self) -> None:
        try:
            import aioquic  # noqa: F401
            self.is_available = True
        except Exception:  # pragma: no cover - environment dependent
            self.is_available = False
        self._connected = False

    def connect(self, url: str) -> None:
        if not self.is_available:  # pragma: no cover
            raise NotImplementedError("QUIC not available in this environment")
        # Placeholder for future implementation
        self._connected = True

    def send(self, payload: bytes) -> None:
        if not self.is_available or not self._connected:  # pragma: no cover
            raise NotImplementedError("QUIC send not available")

    def recv(self, max_bytes: int = 65536) -> bytes:
        if not self.is_available or not self._connected:  # pragma: no cover
            raise NotImplementedError("QUIC recv not available")
        return b""

    def close(self) -> None:
        self._connected = False


