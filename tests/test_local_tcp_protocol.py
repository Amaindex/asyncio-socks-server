import asyncio
from socket import AF_INET, AF_INET6, gaierror, inet_pton
from unittest.mock import Mock, call, patch

import pytest

from asyncio_socks_server.authenticators import NoAuthenticator, UPAuthenticator
from asyncio_socks_server.config import Config
from asyncio_socks_server.protocols import LocalTCP
from asyncio_socks_server.values import SocksAtyp, SocksAuthMethod, Socks5Rep


@pytest.mark.parametrize(
    "method,cls",
    [
        (SocksAuthMethod.NO_AUTH, NoAuthenticator),
        (SocksAuthMethod.UP_AUTH, UPAuthenticator),
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
    transport.is_closing = Mock(return_value=False)

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

    # Invalid version
    # VER, NMETHODS = b"\x06\x02"
    local_tcp.data_received(b"\x06\x02")

    # NoVersionAllowed
    with pytest.raises(asyncio.exceptions.CancelledError):
        asyncio.get_event_loop().run_until_complete(local_tcp.negotiate_task)


def test_negotiate_with_invalid_auth_method(mock_transport):
    config = Config()
    local_tcp = LocalTCP(config)
    local_tcp.connection_made(mock_transport)

    # VER, NMETHODS = b"\x05\x02"
    local_tcp.data_received(b"\x05\x02")
    # Invalid methods
    # METHOD1, METHOD2 = b"\xFD\xFE"
    local_tcp.data_received(b"\xFD\xFE")

    with pytest.raises(asyncio.exceptions.CancelledError):
        asyncio.get_event_loop().run_until_complete(local_tcp.negotiate_task)

    # NoAuthMethodAllowed
    calls = [call(b"\x05\xff")]
    local_tcp.transport.write.assert_has_calls(calls)


def test_negotiate_with_wrong_username_password(mock_transport):
    config = Config()
    config.AUTH_METHOD = SocksAuthMethod.UP_AUTH
    UNAME = "name"
    PASSWD = "password"
    config.USERS = {UNAME: PASSWD}
    local_tcp = LocalTCP(config)
    local_tcp.connection_made(mock_transport)

    # VER, NMETHODS = b"\x05\x02"
    local_tcp.data_received(b"\x05\x02")
    # METHOD1, METHOD2 = b"\x00\x02"
    local_tcp.data_received(b"\x00\x02")

    # Wrong name and password
    # VER, WULEN, WUNAME, WPLEN, WPASSWD
    VER = b"\x01"
    WUNAME = "wrong_name".encode("ASCII")
    WPASSWD = "wrong_password".encode("ASCII")
    local_tcp.data_received(
        VER
        + int.to_bytes(len(WUNAME), 1, "big")
        + WUNAME
        + int.to_bytes(len(WPASSWD), 1, "big")
        + WPASSWD
    )

    with pytest.raises(asyncio.exceptions.CancelledError):
        asyncio.get_event_loop().run_until_complete(local_tcp.negotiate_task)

    # AuthenticationError
    calls = [call(b"\x05\02"), call(b"\x01\x01")]
    local_tcp.transport.write.assert_has_calls(calls)


def test_negotiate_with_no_allowed_ip(mock_transport):
    config = Config()
    config.NETWORKS = ["192.168.88.0/24", "10.233.4.1"]
    local_tcp = LocalTCP(config)
    local_tcp.connection_made(mock_transport)
    local_tcp.peername = ["10.233.4.2", 80]
    # VER, NMETHODS = b"\x05\x01"
    local_tcp.data_received(b"\x05\x01")
    # METHOD = b"\x00"
    local_tcp.data_received(b"\x00")
    with pytest.raises(asyncio.exceptions.CancelledError):
        asyncio.get_event_loop().run_until_complete(local_tcp.negotiate_task)

    # NoAddressAllowed
    local_tcp
    local_tcp.transport.write.assert_called_with(LocalTCP.gen_socks5_reply(Socks5Rep.ADDRESS_NOT_ALLOWED))


@pytest.fixture()
def local_tcp_after_no_auth(mock_transport):
    config = Config()
    local_tcp = LocalTCP(config)
    local_tcp.connection_made(mock_transport)

    # VER, NMETHODS = b"\x05\x01"
    local_tcp.data_received(b"\x05\x01")
    # METHOD = b"\x00"
    local_tcp.data_received(b"\x00")

    return local_tcp


def test_negotiate_with_invalid_atyp(local_tcp_after_no_auth):
    # Invalid address type
    # VER, CMD, RSV, ATYP = b"\x05\x01\x00\xff"
    local_tcp_after_no_auth.data_received(b"\x05\x01\x00\xff")

    with pytest.raises(asyncio.exceptions.CancelledError):
        asyncio.get_event_loop().run_until_complete(
            local_tcp_after_no_auth.negotiate_task
        )

    # NoAtypAllowed
    local_tcp_after_no_auth.transport.write.assert_called_with(
        LocalTCP.gen_socks5_reply(Socks5Rep.ADDRESS_TYPE_NOT_SUPPORTED)
    )


@pytest.mark.parametrize(
    "exception,status",
    [
        (ConnectionRefusedError, Socks5Rep.CONNECTION_REFUSED),
        (gaierror, Socks5Rep.HOST_UNREACHABLE),
        (asyncio.TimeoutError, Socks5Rep.GENERAL_SOCKS_SERVER_FAILURE),
    ],
)
def test_negotiate_with_connect_exceptions(
        local_tcp_after_no_auth, exception, status: Socks5Rep
):
    # VER, CMD, RSV = b"\x05\x01\x00"
    local_tcp_after_no_auth.data_received(b"\x05\x01\x00")
    ATYP = SocksAtyp.IPV4
    local_tcp_after_no_auth.data_received(int.to_bytes(ATYP, 1, "big"))
    # DST_ADDR, DST_PORT = "127.0.0.1", 80
    DST_ADDR = "127.0.0.1"
    local_tcp_after_no_auth.data_received(inet_pton(AF_INET, DST_ADDR))
    DST_PORT = 80
    local_tcp_after_no_auth.data_received(int.to_bytes(DST_PORT, 2, "big"))

    loop = asyncio.get_event_loop()
    patcher_create_connection = patch.object(loop, "create_connection")
    mock_create_connection = patcher_create_connection.start()

    async def mock_create_connection_task():
        raise exception

    mock_create_connection.return_value = loop.create_task(
        mock_create_connection_task()
    )
    with pytest.raises(asyncio.exceptions.CancelledError):
        asyncio.get_event_loop().run_until_complete(
            local_tcp_after_no_auth.negotiate_task
        )

    # patcher_create_connection.stop()

    local_tcp_after_no_auth.transport.write.assert_called_with(
        LocalTCP.gen_socks5_reply(status)
    )


@pytest.mark.parametrize(
    "exception,status",
    [
        (ConnectionRefusedError, Socks5Rep.GENERAL_SOCKS_SERVER_FAILURE),
        (asyncio.TimeoutError, Socks5Rep.GENERAL_SOCKS_SERVER_FAILURE),
    ],
)
def test_negotiate_with_udp_associate_exception(
        local_tcp_after_no_auth, exception, status: Socks5Rep
):
    # VER, CMD, RSV = b"\x05\x03\x00"
    local_tcp_after_no_auth.data_received(b"\x05\x03\x00")
    ATYP = SocksAtyp.IPV4
    local_tcp_after_no_auth.data_received(int.to_bytes(ATYP, 1, "big"))
    # DST_ADDR, DST_PORT = "0.0.0.0", 0
    DST_ADDR = "0.0.0.0"
    local_tcp_after_no_auth.data_received(inet_pton(AF_INET, DST_ADDR))
    DST_PORT = 0
    local_tcp_after_no_auth.data_received(int.to_bytes(DST_PORT, 2, "big"))

    loop = asyncio.get_event_loop()
    patcher_create_datagram_endpoint = patch.object(loop, "create_datagram_endpoint")
    mock_create_datagram_endpoint = patcher_create_datagram_endpoint.start()

    async def mock_create_datagram_endpoint_task():
        raise exception

    mock_create_datagram_endpoint.return_value = loop.create_task(
        mock_create_datagram_endpoint_task()
    )
    with pytest.raises(asyncio.exceptions.CancelledError):
        asyncio.get_event_loop().run_until_complete(
            local_tcp_after_no_auth.negotiate_task
        )

    # patcher_create_datagram_endpoint.stop()

    local_tcp_after_no_auth.transport.write.assert_called_with(
        LocalTCP.gen_socks5_reply(status)
    )


# def test_negotiate_with_connect(local_tcp_after_no_auth):
#     # VER, CMD, RSV = b"\x05\x01\x00"
#     local_tcp_after_no_auth.data_received(b"\x05\x01\x00")
#     ATYP = SocksAtyp.IPV4
#     local_tcp_after_no_auth.data_received(int.to_bytes(ATYP, 1, "big"))
#     # DST_ADDR, DST_PORT = "127.0.0.1", 80
#     DST_ADDR = "127.0.0.1"
#     local_tcp_after_no_auth.data_received(inet_pton(AF_INET, DST_ADDR))
#     DST_PORT = 80
#     local_tcp_after_no_auth.data_received(int.to_bytes(DST_PORT, 2, "big"))
#
#     loop = asyncio.get_event_loop()
#     patcher_create_connection = patch.object(loop, "create_connection")
#     patcher_wait_for = patch("asyncio.wait_for")
#
#     patcher_create_connection.start()
#     mock_wait_for = patcher_wait_for.start()
#
#     mock_remote_tcp = Mock()
#     mock_remote_tcp_transport = Mock()
#     mock_remote_tcp_transport.get_extra_info = Mock(return_value=("0.0.0.0", 9999))
#     mock_wait_for.return_value = (mock_remote_tcp_transport, mock_remote_tcp)
#     asyncio.get_event_loop().run_until_complete(local_tcp_after_no_auth.negotiate_task)
#
#     # patcher_create_connection.stop()
#     # patcher_wait_for.stop()
#
#     bind_addr, bind_port = mock_remote_tcp_transport.get_extra_info("sockname")
#     local_tcp_after_no_auth.transport.write.assert_called_with(
#         LocalTCP.gen_socks5_reply(Socks5Rep.SUCCEEDED, bind_addr, bind_port)
#     )
#     assert local_tcp_after_no_auth.remote_tcp is mock_remote_tcp
#
#
# def test_negotiate_with_udp_associate(local_tcp_after_no_auth):
#     # VER, CMD, RSV = b"\x05\x03\x00"
#     local_tcp_after_no_auth.data_received(b"\x05\x03\x00")
#     ATYP = SocksAtyp.IPV4
#     local_tcp_after_no_auth.data_received(int.to_bytes(ATYP, 1, "big"))
#     # DST_ADDR, DST_PORT = "0.0.0.0", 0
#     DST_ADDR = "0.0.0.0"
#     local_tcp_after_no_auth.data_received(inet_pton(AF_INET, DST_ADDR))
#     DST_PORT = 0
#     local_tcp_after_no_auth.data_received(int.to_bytes(DST_PORT, 2, "big"))
#
#     loop = asyncio.get_event_loop()
#     patcher_create_datagram_endpoint = patch.object(loop, "create_datagram_endpoint")
#     patcher_wait_for = patch("asyncio.wait_for")
#
#     patcher_create_datagram_endpoint.start()
#     mock_wait_for = patcher_wait_for.start()
#
#     mock_local_udp = Mock()
#     mock_local_udp_transport = Mock()
#     mock_local_udp_transport.get_extra_info = Mock(return_value=("0.0.0.0", 0))
#     mock_wait_for.return_value = (mock_local_udp_transport, mock_local_udp)
#     asyncio.get_event_loop().run_until_complete(local_tcp_after_no_auth.negotiate_task)
#
#     # patcher_create_connection.stop()
#     # patcher_wait_for.stop()
#
#     bind_addr, bind_port = mock_local_udp_transport.get_extra_info("sockname")
#     local_tcp_after_no_auth.transport.write.assert_called_with(
#         LocalTCP.gen_socks5_reply(Socks5Rep.SUCCEEDED, bind_addr, bind_port)
#     )
#     assert local_tcp_after_no_auth.local_udp is mock_local_udp
#
#
# @pytest.fixture()
# def local_tcp_after_username_password_auth(mock_transport):
#     config = Config()
#     config.AUTH_METHOD = SocksAuthMethod.UP_AUTH
#     UNAME = "name"
#     PASSWD = "password"
#     config.USERS = {UNAME: PASSWD}
#     local_tcp = LocalTCP(config)
#     local_tcp.connection_made(mock_transport)
#
#     # VER, NMETHODS = b"\x05\x02"
#     local_tcp.data_received(b"\x05\x02")
#     # METHOD1, METHOD2 = b"\x00\x02"
#     local_tcp.data_received(b"\x00\x02")
#
#     # VER, ULEN, UNAME, PLEN, PASSWD
#     VER = b"\x01"
#     local_tcp.data_received(
#         VER
#         + int.to_bytes(len(UNAME.encode("ASCII")), 1, "big")
#         + UNAME.encode("ASCII")
#         + int.to_bytes(len(PASSWD.encode("ASCII")), 1, "big")
#         + PASSWD.encode("ASCII")
#     )
#
#     return local_tcp


# def test_negotiate_with_connect_and_username_password_auth(
#     local_tcp_after_username_password_auth,
# ):
#     # VER, CMD, RSV = b"\x05\x01\x00"
#     local_tcp_after_username_password_auth.data_received(b"\x05\x01\x00")
#     ATYP = SocksAtyp.IPV4
#     local_tcp_after_username_password_auth.data_received(int.to_bytes(ATYP, 1, "big"))
#     # DST_ADDR, DST_PORT = "127.0.0.1", 80
#     DST_ADDR = "127.0.0.1"
#     local_tcp_after_username_password_auth.data_received(inet_pton(AF_INET, DST_ADDR))
#     DST_PORT = 80
#     local_tcp_after_username_password_auth.data_received(
#         int.to_bytes(DST_PORT, 2, "big")
#     )
#
#     loop = asyncio.get_event_loop()
#     patcher_create_connection = patch.object(loop, "create_connection")
#     patcher_wait_for = patch("asyncio.wait_for")
#
#     patcher_create_connection.start()
#     mock_wait_for = patcher_wait_for.start()
#
#     mock_remote_tcp = Mock()
#     mock_remote_tcp_transport = Mock()
#     mock_remote_tcp_transport.get_extra_info = Mock(return_value=("0.0.0.0", 9999))
#     mock_wait_for.return_value = (mock_remote_tcp_transport, mock_remote_tcp)
#     asyncio.get_event_loop().run_until_complete(
#         local_tcp_after_username_password_auth.negotiate_task
#     )
#
#     # patcher_create_connection.stop()
#     # patcher_wait_for.stop()
#
#     bind_addr, bind_port = mock_remote_tcp_transport.get_extra_info("sockname")
#     local_tcp_after_username_password_auth.transport.write.assert_called_with(
#         LocalTCP.gen_socks5_reply(Socks5Rep.SUCCEEDED, bind_addr, bind_port)
#     )
#     assert local_tcp_after_username_password_auth.remote_tcp is mock_remote_tcp


def test_data_received_with_connect(mock_transport):
    config = Config()
    local_tcp = LocalTCP(config)

    local_tcp.stage = local_tcp.STAGE_CONNECT
    local_tcp.remote_tcp = Mock()

    data = "hello world".encode()
    local_tcp.data_received(data)

    local_tcp.remote_tcp.write.assert_called_with(data)


def test_data_received_with_udp_associate(mock_transport):
    config = Config()
    local_tcp = LocalTCP(config)

    local_tcp.stage = local_tcp.STAGE_UDP_ASSOCIATE
    local_tcp.remote_tcp = Mock()

    data = "hello world".encode()
    local_tcp.data_received(data)

    local_tcp.remote_tcp.write.assert_not_called()


def test_flow_control():
    config = Config()
    local_tcp = LocalTCP(config)

    local_tcp.stage = local_tcp.STAGE_CONNECT
    local_tcp.remote_tcp = Mock()
    local_tcp.remote_tcp.transport = Mock()

    local_tcp.pause_writing()
    local_tcp.remote_tcp.transport.pause_reading.assert_called()

    local_tcp.resume_writing()
    local_tcp.remote_tcp.transport.resume_reading.assert_called()


def test_close():
    config = Config()
    local_tcp = LocalTCP(config)

    local_tcp.stage = local_tcp.STAGE_CONNECT
    local_tcp.negotiate_task = Mock()
    local_tcp.transport = Mock()
    local_tcp.remote_tcp = Mock()
    local_tcp.local_udp = Mock()

    local_tcp.close()

    assert local_tcp.stage == local_tcp.STAGE_DESTROY
    local_tcp.negotiate_task.cancel.assert_called()
    local_tcp.transport.close.assert_called()
    local_tcp.remote_tcp.close.assert_called()
    local_tcp.local_udp.close.assert_called()
