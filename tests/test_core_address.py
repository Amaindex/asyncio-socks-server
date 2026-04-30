import asyncio

from asyncio_socks_server.core.address import (
    decode_address,
    detect_atyp,
    encode_address,
    encode_reply,
)
from asyncio_socks_server.core.types import Atyp, Rep


class TestDetectAtyp:
    def test_ipv4(self):
        assert detect_atyp("127.0.0.1") == Atyp.IPV4
        assert detect_atyp("0.0.0.0") == Atyp.IPV4

    def test_ipv6(self):
        assert detect_atyp("::1") == Atyp.IPV6
        assert detect_atyp("2001:db8::1") == Atyp.IPV6

    def test_domain(self):
        assert detect_atyp("example.com") == Atyp.DOMAIN
        assert detect_atyp("sub.example.com") == Atyp.DOMAIN


class TestEncodeDecodeAddress:
    def _roundtrip(self, host: str, port: int):
        encoded = encode_address(host, port)
        reader = asyncio.StreamReader()

        async def do():
            reader.feed_data(encoded)
            reader.feed_eof()
            return await decode_address(reader)

        result = asyncio.get_event_loop().run_until_complete(do())
        return result

    def test_ipv4_roundtrip(self):
        result = self._roundtrip("127.0.0.1", 1080)
        assert result.host == "127.0.0.1"
        assert result.port == 1080

    def test_ipv6_roundtrip(self):
        result = self._roundtrip("::1", 443)
        assert result.host == "::1"
        assert result.port == 443

    def test_domain_roundtrip(self):
        result = self._roundtrip("example.com", 80)
        assert result.host == "example.com"
        assert result.port == 80

    def test_encode_ipv4_binary(self):
        # ATYP(1) + IPv4(4) + PORT(2) = 7 bytes
        data = encode_address("0.0.0.0", 0)
        assert len(data) == 7
        assert data[0] == 0x01

    def test_encode_ipv6_binary(self):
        # ATYP(1) + IPv6(16) + PORT(2) = 19 bytes
        data = encode_address("::1", 0)
        assert len(data) == 19
        assert data[0] == 0x04

    def test_encode_domain_binary(self):
        # ATYP(1) + LEN(1) + "example.com"(11) + PORT(2) = 15 bytes
        data = encode_address("example.com", 80)
        assert len(data) == 15
        assert data[0] == 0x03
        assert data[1] == 11


class TestEncodeReply:
    def test_success_reply(self):
        reply = encode_reply(Rep.SUCCEEDED, "0.0.0.0", 0)
        assert reply[0] == 0x05  # VER
        assert reply[1] == 0x00  # REP = succeeded
        assert reply[2] == 0x00  # RSV

    def test_failure_reply(self):
        reply = encode_reply(Rep.CONNECTION_REFUSED)
        assert reply[1] == 0x05  # REP = connection refused
