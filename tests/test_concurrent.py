"""Concurrency and stress tests."""

import asyncio

from asyncio_socks_server import TrafficCounter
from asyncio_socks_server.core.types import Address
from tests.conftest import _start_server, _stop_server


async def _socks5_proxy_connect(proxy: Address, target: Address):
    """Quick SOCKS5 CONNECT through proxy."""
    reader, writer = await asyncio.open_connection(proxy.host, proxy.port)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    resp = await reader.readexactly(2)
    assert resp == b"\x05\x00"

    from asyncio_socks_server.core.address import encode_address

    writer.write(b"\x05\x01\x00" + encode_address(target.host, target.port))
    await writer.drain()
    reply = await reader.readexactly(3)
    assert reply[1] == 0x00

    atyp = (await reader.readexactly(1))[0]
    if atyp == 0x01:
        await reader.readexactly(4 + 2)
    elif atyp == 0x04:
        await reader.readexactly(16 + 2)
    elif atyp == 0x03:
        length = (await reader.readexactly(1))[0]
        await reader.readexactly(length + 2)
    return reader, writer


class TestConcurrentConnections:
    async def test_20_simultaneous_connections(self, echo_server):
        server, task = await _start_server()
        try:
            conns = await asyncio.gather(
                *[
                    _socks5_proxy_connect(
                        Address(server.host, server.port), echo_server
                    )
                    for _ in range(20)
                ]
            )

            # Send data on all
            for r, w in conns:
                w.write(b"ping")
                await w.drain()

            # Read all responses
            for r, w in conns:
                data = await asyncio.wait_for(r.read(4096), timeout=2.0)
                assert data == b"ping"
                w.close()
                await w.wait_closed()
        finally:
            await _stop_server(server, task)

    async def test_concurrent_with_addon(self, echo_server):
        counter = TrafficCounter()
        server, task = await _start_server(addons=[counter])
        try:
            conns = await asyncio.gather(
                *[
                    _socks5_proxy_connect(
                        Address(server.host, server.port), echo_server
                    )
                    for _ in range(10)
                ]
            )
            for r, w in conns:
                w.write(b"test")
                await w.drain()
            for r, w in conns:
                await r.read(4096)
                w.close()
                await w.wait_closed()
            await asyncio.sleep(0.3)
            assert counter.bytes_up == 40  # 10 * 4 bytes
            assert counter.bytes_down == 40
            assert counter.connections == 10
        finally:
            await _stop_server(server, task)


class TestLargePayloads:
    async def test_1mb_payload(self, echo_server):
        server, task = await _start_server()
        try:
            r, w = await _socks5_proxy_connect(
                Address(server.host, server.port), echo_server
            )
            payload = b"A" * (1024 * 1024)
            w.write(payload)
            await w.drain()

            received = b""
            while len(received) < len(payload):
                chunk = await asyncio.wait_for(r.read(65536), timeout=5.0)
                if not chunk:
                    break
                received += chunk
            assert received == payload

            w.close()
            await w.wait_closed()
        finally:
            await _stop_server(server, task)

    async def test_many_small_writes(self, echo_server):
        server, task = await _start_server()
        try:
            r, w = await _socks5_proxy_connect(
                Address(server.host, server.port), echo_server
            )
            expected = b"".join(f"msg{i:03d}".encode() for i in range(100))
            w.write(expected)
            await w.drain()

            # Read all echoed data
            total = b""
            while len(total) < len(expected):
                chunk = await asyncio.wait_for(r.read(65536), timeout=3.0)
                if not chunk:
                    break
                total += chunk

            assert total == expected
            w.close()
            await w.wait_closed()
        finally:
            await _stop_server(server, task)


class TestRapidConnectDisconnect:
    async def test_rapid_10_cycles(self):
        server, task = await _start_server()
        try:
            for _ in range(10):
                r, w = await asyncio.open_connection(server.host, server.port)
                w.write(b"\x05\x01\x00")
                await w.drain()
                resp = await r.readexactly(2)
                assert resp == b"\x05\x00"
                w.close()
                await w.wait_closed()

            # Verify server is still responsive
            r, w = await asyncio.open_connection(server.host, server.port)
            w.write(b"\x05\x01\x00")
            await w.drain()
            resp = await r.readexactly(2)
            assert resp == b"\x05\x00"
            w.close()
            await w.wait_closed()
        finally:
            await _stop_server(server, task)
