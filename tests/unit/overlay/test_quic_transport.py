from atous_sec_network.overlay.quic_transport import QuicTransport


def test_quic_transport_availability():
    qt = QuicTransport()
    # In CI/dev env w/o aioquic, it should be false
    assert hasattr(qt, "is_available")
    assert isinstance(qt.is_available, bool)


