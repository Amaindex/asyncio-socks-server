import asyncio

import pytest

from asyncio_socks_server.core.types import Address
from asyncio_socks_server.server.server import Server


@pytest.fixture
async def echo_server():
    """TCP echo server for testing."""

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


@pytest.fixture
async def udp_echo_server():
    """UDP echo server for testing."""
    received = []

    class Protocol(asyncio.DatagramProtocol):
        def connection_made(self, transport):
            self.transport = transport

        def datagram_received(self, data, addr):
            received.append((data, addr))
            self.transport.sendto(data, addr)

    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        Protocol, local_addr=("127.0.0.1", 0)
    )
    sock = transport.get_extra_info("socket")
    sockname = sock.getsockname() if sock else ("127.0.0.1", 0)
    yield Address(sockname[0], sockname[1]), received
    transport.close()


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
