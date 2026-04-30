import asyncio

import pytest

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


class TestClientConnect:
    async def test_no_auth(self, echo_server):
        server, task = await _start_server()
        try:
            conn = await connect(Address(server.host, server.port), echo_server)
            conn.writer.write(b"hello")
            await conn.writer.drain()
            data = await conn.reader.read(4096)
            assert data == b"hello"
            conn.writer.close()
            await conn.writer.wait_closed()
        finally:
            await _stop_server(server, task)

    async def test_with_auth(self, echo_server):
        server, task = await _start_server(auth=("user", "pass"))
        try:
            conn = await connect(
                Address(server.host, server.port),
                echo_server,
                username="user",
                password="pass",
            )
            conn.writer.write(b"secret")
            await conn.writer.drain()
            data = await conn.reader.read(4096)
            assert data == b"secret"
            conn.writer.close()
            await conn.writer.wait_closed()
        finally:
            await _stop_server(server, task)

    async def test_auth_failure(self, echo_server):
        server, task = await _start_server(auth=("user", "pass"))
        try:
            from asyncio_socks_server.core.protocol import ProtocolError

            with pytest.raises(ProtocolError, match="authentication failed"):
                await connect(
                    Address(server.host, server.port),
                    echo_server,
                    username="user",
                    password="wrong",
                )
        finally:
            await _stop_server(server, task)

    async def test_connection_refused(self):
        server, task = await _start_server()
        try:
            with pytest.raises(Exception):
                await connect(
                    Address(server.host, server.port),
                    Address("127.0.0.1", 1),  # port 1 should refuse
                )
        finally:
            await _stop_server(server, task)
