"""Server lifecycle tests: startup, shutdown, addon lifecycle during shutdown."""

import asyncio

from asyncio_socks_server.addons.base import Addon
from tests.conftest import _start_server, _stop_server


class StopTracker(Addon):
    def __init__(self):
        self.started = False
        self.stopped = False

    async def on_start(self):
        self.started = True

    async def on_stop(self):
        self.stopped = True


class TestServerStartup:
    async def test_server_binds_to_port(self):
        server, task = await _start_server()
        try:
            assert server.port > 0
        finally:
            await _stop_server(server, task)

    async def test_server_with_zero_port_gets_ephemeral(self):
        server, task = await _start_server()
        try:
            assert server.port > 0
            # Verify we can connect
            _, writer = await asyncio.open_connection(server.host, server.port)
            writer.close()
            await writer.wait_closed()
        finally:
            await _stop_server(server, task)


class TestServerShutdown:
    async def test_request_shutdown_stops_server(self):
        server, task = await _start_server()
        await _stop_server(server, task)
        # Task should be done
        assert task.done()

    async def test_shutdown_calls_addon_stop(self):
        tracker = StopTracker()
        server, task = await _start_server(addons=[tracker])
        assert tracker.started
        await _stop_server(server, task)
        assert tracker.stopped

    async def test_shutdown_closes_listening_socket(self):
        server, task = await _start_server()
        port = server.port
        await _stop_server(server, task)

        # New connections should be refused
        for _ in range(5):
            try:
                _, writer = await asyncio.open_connection(server.host, port)
                writer.close()
                await writer.wait_closed()
                # Connection succeeded — server might still be closing
                await asyncio.sleep(0.1)
            except (ConnectionError, OSError):
                return  # Expected
        # Should have failed by now
        assert False, "Server should have closed listening socket"
