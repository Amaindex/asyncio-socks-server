import pytest
import asyncio
from asyncio_socks_server.protocols import LocalTCP
from asyncio_socks_server.values import AuthMethods
from asyncio_socks_server.config import Config
from asyncio_socks_server.authenticators import NoAuthenticator, PasswordAuthenticator

from unittest.mock import Mock, call


@pytest.mark.parametrize(
    "method,cls",
    [
        (AuthMethods.NO_AUTH, NoAuthenticator),
        (AuthMethods.PASSWORD_AUTH, PasswordAuthenticator),
    ],
)
def test_init_authenticator_cls(method, cls):
    config = Config()
    config.AUTH_METHOD = method
    local_tcp = LocalTCP(config)
    assert local_tcp.authenticator_cls == cls


@pytest.fixture
def mock_transport():
    transport = Mock()
    transport.get_extra_info = Mock(return_value=("0.0.0.0", 0))
    transport.write = Mock()

    return transport


def test_connection_made(mock_transport):
    config = Config()
    local_tcp = LocalTCP(config)

    local_tcp.connection_made(mock_transport)

    assert local_tcp.transport is mock_transport
    assert local_tcp.peername == ("0.0.0.0", 0)
    assert local_tcp.stream_reader._transport is mock_transport
    assert local_tcp.negotiate_task != None

    local_tcp.negotiate_task.cancel()


def test_negotiate_with_invalid_socks_version(mock_transport):
    config = Config()
    local_tcp = LocalTCP(config)

    local_tcp.connection_made(mock_transport)

    # VER, NMETHODS = b"\x06\x02"
    local_tcp.data_received(b"\x06\x02")
    asyncio.get_event_loop().run_until_complete(local_tcp.negotiate_task)

    # NoVersionAllowed
    calls = [call(b"\x05\xff")]
    mock_transport.write.assert_has_calls(calls)
