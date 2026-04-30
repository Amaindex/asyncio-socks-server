from asyncio_socks_server.core.types import (
    Address,
    Atyp,
    AuthMethod,
    Cmd,
    Direction,
    Rep,
)


def test_rep_values():
    assert Rep.SUCCEEDED == 0x00
    assert Rep.GENERAL_FAILURE == 0x01
    assert Rep.COMMAND_NOT_SUPPORTED == 0x07


def test_auth_method_values():
    assert AuthMethod.NO_AUTH == 0x00
    assert AuthMethod.USERNAME_PASSWORD == 0x02
    assert AuthMethod.NO_ACCEPTABLE == 0xFF


def test_cmd_values():
    assert Cmd.CONNECT == 0x01
    assert Cmd.UDP_ASSOCIATE == 0x03


def test_atyp_values():
    assert Atyp.IPV4 == 0x01
    assert Atyp.DOMAIN == 0x03
    assert Atyp.IPV6 == 0x04


def test_direction_constants():
    assert Direction.UPSTREAM == "upstream"
    assert Direction.DOWNSTREAM == "downstream"


def test_address_frozen():
    addr = Address("127.0.0.1", 1080)
    assert addr.host == "127.0.0.1"
    assert addr.port == 1080


def test_address_str():
    assert str(Address("127.0.0.1", 1080)) == "127.0.0.1:1080"
    assert str(Address("example.com", 443)) == "example.com:443"
