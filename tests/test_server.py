import asyncio

import pytest

from asyncio_socks_server.addons.base import Addon
from asyncio_socks_server.core.types import Address, Direction
from asyncio_socks_server.server.server import Server


async def _start_server(
    host: str = "127.0.0.1",
    auth: tuple[str, str] | None = None,
    addons: list[Addon] | None = None,
) -> tuple[Server, asyncio.Task]:
    server = Server(host=host, port=0, auth=auth, addons=addons)
    task = asyncio.create_task(server._run())
    # Wait for the server to be ready
    for _ in range(50):
        if server.port != 0:
            break
        await asyncio.sleep(0.01)
    return server, task


async def _stop_server(server: Server, task: asyncio.Task):
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


async def _socks5_connect(
    proxy_addr: Address, target_addr: Address, auth: tuple[str, str] | None = None
):
    reader, writer = await asyncio.open_connection(proxy_addr.host, proxy_addr.port)

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

    writer.write(b"\x05\x01\x00" + encode_address(target_addr.host, target_addr.port))
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


class TestServerConnect:
    async def test_no_auth_connect(self, echo_server):
        server, task = await _start_server()
        try:
            reader, writer = await _socks5_connect(
                Address(server.host, server.port), echo_server
            )
            writer.write(b"hello")
            await writer.drain()
            data = await reader.read(4096)
            assert data == b"hello"
            writer.close()
            await writer.wait_closed()
        finally:
            await _stop_server(server, task)

    async def test_no_auth_rejected_when_auth_required(self, echo_server):
        server, task = await _start_server(auth=("user", "pass"))
        try:
            reader, writer = await asyncio.open_connection(server.host, server.port)
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            resp = await reader.readexactly(2)
            assert resp[1] == 0xFF
            writer.close()
            await writer.wait_closed()
        finally:
            await _stop_server(server, task)

    async def test_auth_success(self, echo_server):
        server, task = await _start_server(auth=("user", "pass"))
        try:
            reader, writer = await _socks5_connect(
                Address(server.host, server.port),
                echo_server,
                auth=("user", "pass"),
            )
            writer.write(b"secret")
            await writer.drain()
            data = await reader.read(4096)
            assert data == b"secret"
            writer.close()
            await writer.wait_closed()
        finally:
            await _stop_server(server, task)

    async def test_auth_failure(self, echo_server):
        server, task = await _start_server(auth=("user", "pass"))
        try:
            reader, writer = await asyncio.open_connection(server.host, server.port)
            writer.write(b"\x05\x01\x02")
            await writer.drain()
            resp = await reader.readexactly(2)
            assert resp[1] == 0x02

            writer.write(b"\x01\x04user\x04xxxx")
            await writer.drain()
            auth_resp = await reader.readexactly(2)
            assert auth_resp == b"\x01\x01"
            writer.close()
            await writer.wait_closed()
        finally:
            await _stop_server(server, task)


class DataCounter(Addon):
    def __init__(self):
        self.bytes_up = 0
        self.bytes_down = 0

    async def on_data(self, direction, data, flow):
        if direction == Direction.UPSTREAM:
            self.bytes_up += len(data)
        else:
            self.bytes_down += len(data)
        return data


class TestServerWithAddon:
    async def test_data_counting(self, echo_server):
        addon = DataCounter()
        server, task = await _start_server(addons=[addon])
        try:
            reader, writer = await _socks5_connect(
                Address(server.host, server.port), echo_server
            )
            writer.write(b"hello world")
            await writer.drain()
            data = await reader.read(4096)
            assert data == b"hello world"
            await asyncio.sleep(0.1)

            assert addon.bytes_up == 11
            assert addon.bytes_down == 11

            writer.close()
            await writer.wait_closed()
        finally:
            await _stop_server(server, task)
