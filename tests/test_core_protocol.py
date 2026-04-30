import asyncio

import pytest

from asyncio_socks_server.core.protocol import (
    ProtocolError,
    build_auth_reply,
    build_method_reply,
    build_udp_header,
    parse_method_selection,
    parse_request,
    parse_udp_header,
    parse_username_password,
)
from asyncio_socks_server.core.types import Address, AuthMethod, Cmd


class TestMethodSelection:
    def test_valid_no_auth(self):
        data = b"\x05\x01\x00"  # VER=5, NMETHODS=1, METHOD=NO_AUTH
        ver, methods = parse_method_selection(data)
        assert ver == 0x05
        assert AuthMethod.NO_AUTH in methods

    def test_valid_username_password(self):
        data = b"\x05\x02\x00\x02"
        ver, methods = parse_method_selection(data)
        assert AuthMethod.NO_AUTH in methods
        assert AuthMethod.USERNAME_PASSWORD in methods

    def test_wrong_version(self):
        with pytest.raises(ProtocolError, match="unsupported SOCKS version"):
            parse_method_selection(b"\x04\x01\x00")

    def test_too_short(self):
        with pytest.raises(ProtocolError, match="too short"):
            parse_method_selection(b"\x05")

    def test_build_method_reply(self):
        assert build_method_reply(0x00) == b"\x05\x00"
        assert build_method_reply(0x02) == b"\x05\x02"
        assert build_method_reply(0xFF) == b"\x05\xff"


class TestUsernamePassword:
    def test_parse(self):
        # VER=1, ULEN=4, UNAME="user", PLEN=4, PASSWD="pass"
        data = b"\x01\x04user\x04pass"
        reader = asyncio.StreamReader()

        async def do():
            reader.feed_data(data)
            reader.feed_eof()
            return await parse_username_password(reader)

        username, password = asyncio.get_event_loop().run_until_complete(do())
        assert username == "user"
        assert password == "pass"

    def test_wrong_version(self):
        data = b"\x02\x04user\x04pass"
        reader = asyncio.StreamReader()

        async def do():
            reader.feed_data(data)
            reader.feed_eof()
            return await parse_username_password(reader)

        with pytest.raises(ProtocolError, match="unsupported auth version"):
            asyncio.get_event_loop().run_until_complete(do())

    def test_build_auth_reply(self):
        assert build_auth_reply(True) == b"\x01\x00"
        assert build_auth_reply(False) == b"\x01\x01"


class TestParseRequest:
    def _make_request(self, cmd: int, host: str, port: int) -> bytes:
        from asyncio_socks_server.core.address import encode_address

        VER = b"\x05"
        CMD = cmd.to_bytes(1, "big")
        RSV = b"\x00"
        return VER + CMD + RSV + encode_address(host, port)

    def test_connect_ipv4(self):
        data = self._make_request(0x01, "127.0.0.1", 1080)
        reader = asyncio.StreamReader()

        async def do():
            reader.feed_data(data)
            reader.feed_eof()
            return await parse_request(reader)

        cmd, addr = asyncio.get_event_loop().run_until_complete(do())
        assert cmd == Cmd.CONNECT
        assert addr.host == "127.0.0.1"
        assert addr.port == 1080

    def test_connect_ipv6(self):
        data = self._make_request(0x01, "::1", 443)
        reader = asyncio.StreamReader()

        async def do():
            reader.feed_data(data)
            reader.feed_eof()
            return await parse_request(reader)

        cmd, addr = asyncio.get_event_loop().run_until_complete(do())
        assert cmd == Cmd.CONNECT
        assert addr.host == "::1"
        assert addr.port == 443

    def test_connect_domain(self):
        data = self._make_request(0x01, "example.com", 80)
        reader = asyncio.StreamReader()

        async def do():
            reader.feed_data(data)
            reader.feed_eof()
            return await parse_request(reader)

        cmd, addr = asyncio.get_event_loop().run_until_complete(do())
        assert cmd == Cmd.CONNECT
        assert addr.host == "example.com"
        assert addr.port == 80

    def test_udp_associate(self):
        data = self._make_request(0x03, "0.0.0.0", 0)
        reader = asyncio.StreamReader()

        async def do():
            reader.feed_data(data)
            reader.feed_eof()
            return await parse_request(reader)

        cmd, addr = asyncio.get_event_loop().run_until_complete(do())
        assert cmd == Cmd.UDP_ASSOCIATE

    def test_wrong_version(self):
        data = b"\x04\x01\x00\x01\x7f\x00\x00\x01\x04\x38"
        reader = asyncio.StreamReader()

        async def do():
            reader.feed_data(data)
            reader.feed_eof()
            return await parse_request(reader)

        with pytest.raises(ProtocolError, match="unsupported SOCKS version"):
            asyncio.get_event_loop().run_until_complete(do())

    def test_unsupported_command(self):
        data = self._make_request(0x02, "127.0.0.1", 1080)  # BIND
        reader = asyncio.StreamReader()

        async def do():
            reader.feed_data(data)
            reader.feed_eof()
            return await parse_request(reader)

        with pytest.raises(ProtocolError, match="unsupported command"):
            asyncio.get_event_loop().run_until_complete(do())


class TestUdpHeader:
    def test_parse_ipv4(self):
        from asyncio_socks_server.core.address import encode_address

        header = b"\x00\x00\x00" + encode_address("127.0.0.1", 1080)
        payload = b"hello"
        data = header + payload

        addr, hdr_len, pl = parse_udp_header(data)
        assert addr.host == "127.0.0.1"
        assert addr.port == 1080
        assert hdr_len == 3 + 7  # RSV(2)+FRAG(1)+ATYP(1)+IPv4(4)+PORT(2)
        assert pl == b"hello"

    def test_parse_domain(self):
        from asyncio_socks_server.core.address import encode_address

        header = b"\x00\x00\x00" + encode_address("example.com", 80)
        payload = b"world"
        data = header + payload

        addr, hdr_len, pl = parse_udp_header(data)
        assert addr.host == "example.com"
        assert addr.port == 80
        assert pl == b"world"

    def test_build_udp_header(self):
        header = build_udp_header(Address("127.0.0.1", 1080))
        assert header[0:2] == b"\x00\x00"  # RSV
        assert header[2] == 0x00  # FRAG
        assert header[3] == 0x01  # ATYP IPv4

    def test_too_short(self):
        with pytest.raises(ProtocolError, match="too short"):
            parse_udp_header(b"\x00\x00")
