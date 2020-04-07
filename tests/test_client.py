from opendrop.client import AirDropBrowser
from opendrop.config import AirDropConfig


def get_loopback():
    import ifaddr
    for adapter in ifaddr.get_adapters():
        if adapter.name.startswith('lo'):
            return adapter.name
    return None


def test_browser_setup():
    loopback = get_loopback()
    assert loopback is not None, 'Could not find loopback interface'
    config = AirDropConfig(interface=loopback)
    browser = AirDropBrowser(config)
    browser.start()
    browser.stop()
