import asyncio
import json

from asyncio_socks_server import Address, Server, StatsServer, connect


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


async def _get_json(port: int, path: str):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".encode("ascii"))
    await writer.drain()
    data = await reader.read()
    writer.close()
    await writer.wait_closed()

    header, body = data.split(b"\r\n\r\n", 1)
    status = int(header.split(b" ", 2)[1])
    return status, json.loads(body)


class TestStatsServer:
    async def test_health_endpoint(self):
        stats = StatsServer()
        server, task = await _start_server(addons=[stats])
        try:
            status, payload = await _get_json(stats.port, "/health")
            assert status == 200
            assert payload == {"ok": True}
        finally:
            await _stop_server(server, task)

    async def test_tracks_active_and_closed_tcp_flows(self, echo_server):
        stats = StatsServer()
        server, task = await _start_server(addons=[stats])
        try:
            conn = await connect(Address(server.host, server.port), echo_server)
            conn.writer.write(b"stats")
            await conn.writer.drain()
            data = await conn.reader.read(4096)
            assert data == b"stats"

            status, payload = await _get_json(stats.port, "/stats")
            assert status == 200
            assert payload["active_flows"] == 1
            assert payload["total_flows"] == 1
            assert payload["total_tcp_flows"] == 1
            assert payload["active"][0]["bytes_up"] == 5
            assert payload["active"][0]["bytes_down"] == 5

            conn.writer.close()
            await conn.writer.wait_closed()
            await asyncio.sleep(0.05)

            status, flows = await _get_json(stats.port, "/flows")
            assert status == 200
            assert flows["active"] == []
            assert len(flows["recent_closed"]) == 1
            assert flows["recent_closed"][0]["bytes_up"] == 5
            assert flows["recent_closed"][0]["bytes_down"] == 5

            snapshot = stats.snapshot()
            assert snapshot["active_flows"] == 0
            assert snapshot["closed_flows"] == 1
            assert snapshot["total_bytes_up"] == 5
            assert snapshot["total_bytes_down"] == 5
        finally:
            await _stop_server(server, task)

    async def test_not_found(self):
        stats = StatsServer()
        server, task = await _start_server(addons=[stats])
        try:
            status, payload = await _get_json(stats.port, "/missing")
            assert status == 404
            assert payload == {"error": "not found"}
        finally:
            await _stop_server(server, task)
