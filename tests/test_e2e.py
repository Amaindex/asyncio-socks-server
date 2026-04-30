"""End-to-end tests: full proxy scenarios."""

import asyncio

from asyncio_socks_server import Addon, ChainRouter, TrafficCounter, connect
from asyncio_socks_server.core.types import Address


async def _socks5_proxy_connect(proxy: Address, target: Address, auth=None):
    """Raw SOCKS5 CONNECT through proxy."""
    reader, writer = await asyncio.open_connection(proxy.host, proxy.port)

    if auth:
        writer.write(b"\x05\x01\x02")
    else:
        writer.write(b"\x05\x01\x00")
    await writer.drain()

    resp = await reader.readexactly(2)
    assert resp[0] == 0x05

    if auth:
        assert resp[1] == 0x02
        uname = auth[0].encode()
        passwd = auth[1].encode()
        writer.write(
            b"\x01"
            + len(uname).to_bytes(1, "big")
            + uname
            + len(passwd).to_bytes(1, "big")
            + passwd
        )
        await writer.drain()
        auth_resp = await reader.readexactly(2)
        assert auth_resp == b"\x01\x00"
    else:
        assert resp[1] == 0x00

    from asyncio_socks_server.core.address import encode_address

    writer.write(b"\x05\x01\x00" + encode_address(target.host, target.port))
    await writer.drain()

    reply = await reader.readexactly(3)
    assert reply[1] == 0x00  # succeeded

    # Skip bound address
    atyp = (await reader.readexactly(1))[0]
    if atyp == 0x01:
        await reader.readexactly(4 + 2)
    elif atyp == 0x04:
        await reader.readexactly(16 + 2)
    elif atyp == 0x03:
        length = (await reader.readexactly(1))[0]
        await reader.readexactly(length + 2)

    return reader, writer


class TestE2ETcp:
    async def test_bidirectional_relay(self, echo_server):
        from tests.conftest import _start_server, _stop_server

        server, task = await _start_server()
        try:
            r, w = await _socks5_proxy_connect(
                Address(server.host, server.port), echo_server
            )
            w.write(b"ping")
            await w.drain()
            assert await r.read(4096) == b"ping"

            w.write(b"pong")
            await w.drain()
            assert await r.read(4096) == b"pong"

            w.close()
            await w.wait_closed()
        finally:
            await _stop_server(server, task)

    async def test_multiple_connections(self, echo_server):
        from tests.conftest import _start_server, _stop_server

        server, task = await _start_server()
        try:
            conns = []
            for _ in range(5):
                r, w = await _socks5_proxy_connect(
                    Address(server.host, server.port), echo_server
                )
                conns.append((r, w))

            for r, w in conns:
                w.write(b"test")
                await w.drain()
                assert await r.read(4096) == b"test"
                w.close()
                await w.wait_closed()
        finally:
            await _stop_server(server, task)

    async def test_client_library(self, echo_server):
        from tests.conftest import _start_server, _stop_server

        server, task = await _start_server()
        try:
            conn = await connect(Address(server.host, server.port), echo_server)
            conn.writer.write(b"via client library")
            await conn.writer.drain()
            data = await conn.reader.read(4096)
            assert data == b"via client library"
            conn.writer.close()
            await conn.writer.wait_closed()
        finally:
            await _stop_server(server, task)


class TestE2EChain:
    async def test_three_hop_chain(self, echo_server):
        from tests.conftest import _start_server, _stop_server

        exit_server, exit_task = await _start_server()

        mid_addon = ChainRouter(next_hop=f"127.0.0.1:{exit_server.port}")
        mid_server, mid_task = await _start_server(addons=[mid_addon])

        entry_addon = ChainRouter(next_hop=f"127.0.0.1:{mid_server.port}")
        entry_server, entry_task = await _start_server(addons=[entry_addon])

        try:
            conn = await connect(
                Address(entry_server.host, entry_server.port), echo_server
            )
            conn.writer.write(b"three hops!")
            await conn.writer.drain()
            data = await conn.reader.read(4096)
            assert data == b"three hops!"
            conn.writer.close()
            await conn.writer.wait_closed()
        finally:
            await _stop_server(entry_server, entry_task)
            await _stop_server(mid_server, mid_task)
            await _stop_server(exit_server, exit_task)


class UpperAddon(Addon):
    async def on_data(self, direction, data, flow):
        return data.upper()


class TestE2EAddons:
    async def test_pipeline_transform(self, echo_server):
        from tests.conftest import _start_server, _stop_server

        server, task = await _start_server(addons=[UpperAddon()])
        try:
            r, w = await _socks5_proxy_connect(
                Address(server.host, server.port), echo_server
            )
            w.write(b"hello")
            await w.drain()

            # Echo server receives "HELLO" and echoes it back
            # The upstream addon transforms to uppercase
            # The downstream addon also transforms, but echo returns it
            data = await r.read(4096)
            assert data == b"HELLO"

            w.close()
            await w.wait_closed()
        finally:
            await _stop_server(server, task)

    async def test_traffic_counter(self, echo_server):
        from tests.conftest import _start_server, _stop_server

        counter = TrafficCounter()
        server, task = await _start_server(addons=[counter])
        try:
            r, w = await _socks5_proxy_connect(
                Address(server.host, server.port), echo_server
            )
            w.write(b"count me")
            await w.drain()
            await r.read(4096)

            # TrafficCounter now reads from flow on close,
            # so assertions must happen after connection teardown.
            w.close()
            await w.wait_closed()
            await asyncio.sleep(0.2)

            assert counter.bytes_up == 8
            assert counter.bytes_down == 8
            assert counter.connections == 1
        finally:
            await _stop_server(server, task)
