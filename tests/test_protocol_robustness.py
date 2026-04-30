"""Protocol parser edge cases and boundary conditions."""

import asyncio

import pytest

from asyncio_socks_server.core.protocol import (
    ProtocolError,
    parse_method_selection,
    parse_request,
    parse_udp_header,
    parse_username_password,
)


class TestMethodSelectionEdgeCases:
    def test_empty_data(self):
        with pytest.raises(ProtocolError, match="too short"):
            parse_method_selection(b"")

    def test_single_byte(self):
        with pytest.raises(ProtocolError, match="too short"):
            parse_method_selection(b"\x05")

    def test_wrong_version(self):
        with pytest.raises(ProtocolError, match="unsupported SOCKS version"):
            parse_method_selection(b"\x04\x01\x00")

    def test_nmethods_zero(self):
        ver, methods = parse_method_selection(b"\x05\x00")
        assert ver == 0x05
        assert methods == set()

    def test_extra_bytes_beyond_methods(self):
        # NMETHODS=1 but data has 3 bytes — extra ignored
        ver, methods = parse_method_selection(b"\x05\x01\x00\xff\xfe")
        assert ver == 0x05
        assert methods == {0x00}

    def test_all_methods(self):
        data = b"\x05\xff" + bytes(range(255))
        ver, methods = parse_method_selection(data)
        assert len(methods) == 255


class TestUsernamePasswordEdgeCases:
    async def test_empty_username(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b"\x01\x00\x04test")
        reader.feed_eof()
        username, password = await parse_username_password(reader)
        assert username == ""
        assert password == "test"

    async def test_empty_password(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b"\x01\x04test\x00")
        reader.feed_eof()
        username, password = await parse_username_password(reader)
        assert username == "test"
        assert password == ""

    async def test_max_length_username(self):
        reader = asyncio.StreamReader()
        uname = b"a" * 255
        reader.feed_data(b"\x01\xff" + uname + b"\x01x")
        reader.feed_eof()
        username, password = await parse_username_password(reader)
        assert len(username) == 255
        assert password == "x"

    async def test_wrong_auth_version(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b"\x02\x04test\x04test")
        reader.feed_eof()
        with pytest.raises(ProtocolError, match="unsupported auth version"):
            await parse_username_password(reader)

    async def test_truncated_password(self):
        reader = asyncio.StreamReader()
        # Claims PLEN=10 but only provides 4 bytes then EOF
        reader.feed_data(b"\x01\x04test\x0ashor")
        reader.feed_eof()
        with pytest.raises(asyncio.IncompleteReadError):
            await parse_username_password(reader)


class TestParseRequestEdgeCases:
    async def test_unsupported_atyp(self):
        reader = asyncio.StreamReader()
        # VER=5, CMD=CONNECT(1), RSV=0, ATYP=0x05 (invalid)
        reader.feed_data(b"\x05\x01\x00\x05")
        reader.feed_eof()
        with pytest.raises(ProtocolError, match="unsupported ATYP"):
            await parse_request(reader)

    async def test_unsupported_command(self):
        reader = asyncio.StreamReader()
        # VER=5, CMD=0x02 (BIND, not supported), RSV=0, ATYP=1
        reader.feed_data(b"\x05\x02\x00\x01")
        reader.feed_eof()
        with pytest.raises(ProtocolError, match="unsupported command"):
            await parse_request(reader)

    async def test_wrong_version_in_request(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b"\x04\x01\x00\x01")
        reader.feed_eof()
        with pytest.raises(ProtocolError, match="unsupported SOCKS version"):
            await parse_request(reader)

    async def test_ipv4_truncated(self):
        reader = asyncio.StreamReader()
        # ATYP=0x01 (IPv4, needs 4 bytes) but only 2 bytes
        reader.feed_data(b"\x05\x01\x00\x01\x7f\x00")
        reader.feed_eof()
        with pytest.raises(asyncio.IncompleteReadError):
            await parse_request(reader)

    async def test_domain_empty_label(self):
        reader = asyncio.StreamReader()
        # ATYP=0x03, length=0, then 2 port bytes
        reader.feed_data(b"\x05\x01\x00\x03\x00\x00\x50")
        cmd, addr = await parse_request(reader)
        assert addr.host == ""

    async def test_domain_max_length(self):
        reader = asyncio.StreamReader()
        domain = b"a" * 255
        reader.feed_data(b"\x05\x01\x00\x03" + bytes([255]) + domain + b"\x00\x50")
        cmd, addr = await parse_request(reader)
        assert len(addr.host) == 255

    async def test_domain_truncated(self):
        reader = asyncio.StreamReader()
        # Claims domain length 20 but only 5 bytes
        reader.feed_data(b"\x05\x01\x00\x03\x14hello")
        reader.feed_eof()
        with pytest.raises(asyncio.IncompleteReadError):
            await parse_request(reader)

    async def test_port_truncated(self):
        reader = asyncio.StreamReader()
        # IPv4 address present, but only 1 port byte
        reader.feed_data(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00")
        reader.feed_eof()
        with pytest.raises(asyncio.IncompleteReadError):
            await parse_request(reader)


class TestUdpHeaderEdgeCases:
    def test_too_short(self):
        with pytest.raises(ProtocolError, match="too short"):
            parse_udp_header(b"\x00\x00")

    def test_ipv4_truncated(self):
        # ATYP=0x01 but only 2 of 4 IPv4 bytes
        with pytest.raises(ProtocolError, match="truncated"):
            parse_udp_header(b"\x00\x00\x00\x01\x7f\x00")

    def test_ipv6_truncated(self):
        # ATYP=0x04 but only 10 of 16 IPv6 bytes
        with pytest.raises(ProtocolError, match="truncated"):
            parse_udp_header(b"\x00\x00\x00\x04" + b"\x00" * 10)

    def test_domain_truncated(self):
        # ATYP=0x03, length=20 but only 5 domain bytes
        with pytest.raises(ProtocolError, match="truncated"):
            parse_udp_header(b"\x00\x00\x00\x03\x14hello")

    def test_unsupported_atyp(self):
        with pytest.raises(ProtocolError, match="unsupported ATYP"):
            parse_udp_header(b"\x00\x00\x00\x02" + b"\x00" * 10)

    def test_header_only_no_payload(self):
        # Valid IPv4 header with zero payload
        addr, hdr_len, payload = parse_udp_header(
            b"\x00\x00\x00\x01\x7f\x00\x00\x01\x00\x50"
        )
        assert payload == b""
        assert hdr_len == 10

    def test_ipv6_full_roundtrip(self):
        import ipaddress

        ipv6 = ipaddress.IPv6Address("::1").compressed
        header = b"\x00\x00\x00\x04" + ipaddress.IPv6Address("::1").packed + b"\x01\xbb"
        header += b"payload"
        addr, hdr_len, payload = parse_udp_header(header)
        assert addr.host == ipv6
        assert addr.port == 443
        assert payload == b"payload"
        assert hdr_len == 22

    def test_domain_roundtrip(self):
        header = b"\x00\x00\x00\x03\x0bexample.com\x00\x50payload"
        addr, hdr_len, payload = parse_udp_header(header)
        assert addr.host == "example.com"
        assert addr.port == 80
        assert payload == b"payload"
        assert hdr_len == 18
