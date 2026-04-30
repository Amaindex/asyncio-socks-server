import asyncio

from asyncio_socks_server import connect
from asyncio_socks_server.core.types import Address
from tests.conftest import _start_server, _stop_server


class TestClientDisconnect:
    async def test_abrupt_client_disconnect_no_crash(self, echo_server):
        server, task = await _start_server()
        try:
            conn = await connect(Address(server.host, server.port), echo_server)
            conn.writer.write(b"before-disconnect")
            await conn.writer.drain()
            assert await conn.reader.read(4096) == b"before-disconnect"

            conn.writer.close()
            await conn.writer.wait_closed()

            conn2 = await connect(Address(server.host, server.port), echo_server)
            conn2.writer.write(b"after-disconnect")
            await conn2.writer.drain()
            assert await conn2.reader.read(4096) == b"after-disconnect"
            conn2.writer.close()
            await conn2.writer.wait_closed()
        finally:
            await _stop_server(server, task)

    async def test_target_disconnect_mid_relay(self):
        async def disconnect_after_first(reader, writer):
            try:
                data = await reader.read(4096)
                writer.write(data)
                await writer.drain()
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        srv = await asyncio.start_server(disconnect_after_first, "127.0.0.1", 0)
        addr = srv.sockets[0].getsockname()
        target = Address(addr[0], addr[1])

        server, task = await _start_server()
        try:
            conn = await connect(Address(server.host, server.port), target)
            conn.writer.write(b"first")
            await conn.writer.drain()
            assert await conn.reader.read(4096) == b"first"
            assert await conn.reader.read(4096) == b""

            conn.writer.close()
            await conn.writer.wait_closed()
        finally:
            await _stop_server(server, task)
            srv.close()
            await srv.wait_closed()


class TestGracefulShutdown:
    async def test_active_connections_complete_on_shutdown(self):
        async def slow_echo(reader, writer):
            try:
                data = await reader.read(4096)
                await asyncio.sleep(0.2)
                writer.write(data)
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        srv = await asyncio.start_server(slow_echo, "127.0.0.1", 0)
        addr = srv.sockets[0].getsockname()
        target = Address(addr[0], addr[1])

        server, task = await _start_server()
        try:
            conn = await connect(Address(server.host, server.port), target)
            conn.writer.write(b"slow")
            await conn.writer.drain()

            server.request_shutdown()
            data = await asyncio.wait_for(conn.reader.read(4096), timeout=3.0)
            assert data == b"slow"

            conn.writer.close()
            await conn.writer.wait_closed()
        finally:
            await task
            srv.close()
            await srv.wait_closed()


class TestRepeatedConnections:
    async def test_50_sequential_connections(self, echo_server):
        server, task = await _start_server()
        try:
            for i in range(50):
                conn = await connect(Address(server.host, server.port), echo_server)
                msg = f"msg-{i:03d}".encode()
                conn.writer.write(msg)
                await conn.writer.drain()
                assert await conn.reader.read(4096) == msg
                conn.writer.close()
                await conn.writer.wait_closed()
        finally:
            await _stop_server(server, task)

    async def test_connection_reuse_stability(self, echo_server):
        server, task = await _start_server()
        try:
            for round_num in range(3):
                conns = []
                for i in range(10):
                    conn = await connect(Address(server.host, server.port), echo_server)
                    msg = f"r{round_num}-{i}".encode()
                    conn.writer.write(msg)
                    await conn.writer.drain()
                    conns.append((conn, msg))

                for conn, msg in conns:
                    assert await conn.reader.read(4096) == msg
                    conn.writer.close()
                    await conn.writer.wait_closed()

                await asyncio.sleep(0.1)
        finally:
            await _stop_server(server, task)
