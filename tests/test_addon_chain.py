import asyncio

import pytest

from asyncio_socks_server.addons.chain import ChainRouter
from asyncio_socks_server.client.client import connect
from asyncio_socks_server.core.types import Address
from asyncio_socks_server.server.server import Server


async def _start_server(**kwargs):
    server = Server(host="127.0.0.1", port=0, **kwargs)
    task = asyncio.create_task(server._run())
    for _ in range(50):
        if server.port != 0:
            break
        await asyncio.sleep(0.01)
    return server, task


async def _stop_server(server, task):
    server.request_shutdown()
    await task


@pytest.fixture
async def echo_server():
    async def handler(reader, writer):
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    srv = await asyncio.start_server(handler, "127.0.0.1", 0)
    addr = srv.sockets[0].getsockname()
    yield Address(addr[0], addr[1])
    srv.close()
    await srv.wait_closed()


class TestChainRouter:
    async def test_two_hop_chain(self, echo_server):
        # Exit node: direct to target
        exit_server, exit_task = await _start_server()

        # Entry node: routes through exit node
        chain_addon = ChainRouter(next_hop=f"127.0.0.1:{exit_server.port}")
        entry_server, entry_task = await _start_server(addons=[chain_addon])

        try:
            conn = await connect(
                Address(entry_server.host, entry_server.port),
                echo_server,
            )
            conn.writer.write(b"through the chain")
            await conn.writer.drain()
            data = await conn.reader.read(4096)
            assert data == b"through the chain"
            conn.writer.close()
            await conn.writer.wait_closed()
        finally:
            await _stop_server(entry_server, entry_task)
            await _stop_server(exit_server, exit_task)

    async def test_chain_with_auth(self, echo_server):
        exit_server, exit_task = await _start_server(auth=("proxy", "secret"))

        chain_addon = ChainRouter(
            next_hop=f"127.0.0.1:{exit_server.port}",
            username="proxy",
            password="secret",
        )
        entry_server, entry_task = await _start_server(addons=[chain_addon])

        try:
            conn = await connect(
                Address(entry_server.host, entry_server.port),
                echo_server,
            )
            conn.writer.write(b"auth chain")
            await conn.writer.drain()
            data = await conn.reader.read(4096)
            assert data == b"auth chain"
            conn.writer.close()
            await conn.writer.wait_closed()
        finally:
            await _stop_server(entry_server, entry_task)
            await _stop_server(exit_server, exit_task)
