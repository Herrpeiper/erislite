from erislite.deception.odyssey.config import (
    DEFAULT_LISTENERS,
    ListenerConfig,
    get_default_listeners,
)


def test_listener_config_defaults():
    config = ListenerConfig(
        port=8080,
        service="http-alt",
    )

    assert config.port == 8080
    assert config.service == "http-alt"
    assert config.severity == "medium"
    assert config.enabled is True


def test_default_listeners_are_returned():
    listeners = get_default_listeners()

    assert listeners == DEFAULT_LISTENERS
    assert len(listeners) == 5


def test_default_listener_ports_are_unique():
    ports = [listener.port for listener in get_default_listeners()]

    assert len(ports) == len(set(ports))


def test_expected_default_ports_exist():
    ports = {
        listener.port
        for listener in get_default_listeners()
    }

    assert ports == {2121, 2323, 2222, 3389, 8080}