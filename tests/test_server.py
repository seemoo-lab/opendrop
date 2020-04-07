from opendrop.server import AirDropServer
from opendrop.config import AirDropConfig


def get_loopback():
    import ifaddr
    for adapter in ifaddr.get_adapters():
        if adapter.name.startswith('lo'):
            return adapter.name
    return None


def test_server_setup():
    loopback = get_loopback()
    assert loopback is not None, 'Could not find loopback interface'
    config = AirDropConfig(interface=loopback)
    server = AirDropServer(config)
    server.start_service()
    # TODO currently no good way of stopping the server
    # server.start_server()
