import asyncio

from asyncio_socks_server.core.types import Address
from asyncio_socks_server.server.udp_over_tcp import encode_udp_frame, read_udp_frame


class TestUdpOverTcpFrame:
    async def test_roundtrip_ipv4(self):
        addr = Address("127.0.0.1", 1080)
        payload = b"hello world"

        frame = await encode_udp_frame(addr, payload)

        reader = asyncio.StreamReader()
        reader.feed_data(frame)
        reader.feed_eof()

        result_addr, result_data = await read_udp_frame(reader)
        assert result_addr.host == "127.0.0.1"
        assert result_addr.port == 1080
        assert result_data == payload

    async def test_roundtrip_ipv6(self):
        addr = Address("::1", 443)
        payload = b"test data"

        frame = await encode_udp_frame(addr, payload)

        reader = asyncio.StreamReader()
        reader.feed_data(frame)
        reader.feed_eof()

        result_addr, result_data = await read_udp_frame(reader)
        assert result_addr.host == "::1"
        assert result_addr.port == 443
        assert result_data == payload

    async def test_roundtrip_domain(self):
        addr = Address("example.com", 80)
        payload = b"http request"

        frame = await encode_udp_frame(addr, payload)

        reader = asyncio.StreamReader()
        reader.feed_data(frame)
        reader.feed_eof()

        result_addr, result_data = await read_udp_frame(reader)
        assert result_addr.host == "example.com"
        assert result_addr.port == 80
        assert result_data == payload

    async def test_multiple_frames(self):
        frames_data = b""
        expected = []

        for i in range(3):
            addr = Address("127.0.0.1", 1000 + i)
            payload = f"packet {i}".encode()
            frame = await encode_udp_frame(addr, payload)
            frames_data += frame
            expected.append((addr, payload))

        reader = asyncio.StreamReader()
        reader.feed_data(frames_data)
        reader.feed_eof()

        for exp_addr, exp_data in expected:
            result_addr, result_data = await read_udp_frame(reader)
            assert result_addr.host == exp_addr.host
            assert result_addr.port == exp_addr.port
            assert result_data == exp_data

    async def test_empty_payload(self):
        addr = Address("10.0.0.1", 53)
        payload = b""

        frame = await encode_udp_frame(addr, payload)

        reader = asyncio.StreamReader()
        reader.feed_data(frame)
        reader.feed_eof()

        result_addr, result_data = await read_udp_frame(reader)
        assert result_addr.host == "10.0.0.1"
        assert result_addr.port == 53
        assert result_data == b""
