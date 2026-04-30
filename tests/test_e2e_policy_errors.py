import asyncio

from asyncio_socks_server import ChainRouter, IPFilter, connect
from asyncio_socks_server.core.address import encode_address
from asyncio_socks_server.core.types import Address
from tests.conftest import _start_server, _stop_server
from tests.e2e_helpers import read_socks_reply, socks5_connect


class TestIPFilterE2E:
    async def test_allowed_ip_connects(self, echo_server):
        filter_addon = IPFilter(allowed=["127.0.0.0/8"])
        server, task = await _start_server(addons=[filter_addon])
        try:
            conn = await connect(Address(server.host, server.port), echo_server)
            conn.writer.write(b"allowed")
            await conn.writer.drain()
            assert await conn.reader.read(4096) == b"allowed"
            conn.writer.close()
            await conn.writer.wait_closed()
        finally:
            await _stop_server(server, task)

    async def test_blocked_ip_rejected(self, echo_server):
        filter_addon = IPFilter(blocked=["127.0.0.0/8"])
        server, task = await _start_server(addons=[filter_addon])
        try:
            reader, writer = await socks5_connect(
                Address(server.host, server.port), echo_server
            )
            reply = await read_socks_reply(reader)
            assert reply[1] == 0x02
            writer.close()
            await writer.wait_closed()
        finally:
            await _stop_server(server, task)


class TestConnectionRefusedE2E:
    async def test_target_refused_returns_error_reply(self):
        server, task = await _start_server()
        try:
            reader, writer = await socks5_connect(
                Address(server.host, server.port),
                Address("127.0.0.1", 1),
            )
            reply = await read_socks_reply(reader)
            assert reply[1] != 0x00
            writer.close()
            await writer.wait_closed()
        finally:
            await _stop_server(server, task)

    async def test_unreachable_target_through_chain(self):
        exit_server, exit_task = await _start_server()
        chain = ChainRouter(next_hop=f"127.0.0.1:{exit_server.port}")
        entry_server, entry_task = await _start_server(addons=[chain])

        try:
            reader, writer = await socks5_connect(
                Address(entry_server.host, entry_server.port),
                Address("127.0.0.1", 1),
            )
            reply = await read_socks_reply(reader)
            assert reply[1] == 0x02
            writer.close()
            await writer.wait_closed()
        finally:
            await _stop_server(entry_server, entry_task)
            await _stop_server(exit_server, exit_task)


class TestDomainNameTarget:
    async def test_domain_target_resolved(self, echo_server):
        server, task = await _start_server()
        try:
            reader, writer = await asyncio.open_connection(server.host, server.port)

            writer.write(b"\x05\x01\x00")
            await writer.drain()
            assert await reader.readexactly(2) == b"\x05\x00"

            writer.write(
                b"\x05\x01\x00" + encode_address("127.0.0.1", echo_server.port)
            )
            await writer.drain()
            reply = await read_socks_reply(reader)
            assert reply[1] == 0x00

            writer.write(b"domain-test")
            await writer.drain()
            assert await reader.read(4096) == b"domain-test"

            writer.close()
            await writer.wait_closed()
        finally:
            await _stop_server(server, task)
