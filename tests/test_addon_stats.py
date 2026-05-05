import asyncio
import json

from asyncio_socks_server import (
    Address,
    FlowAudit,
    FlowStats,
    Server,
    StatsAPI,
    StatsServer,
    connect,
)


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
    return await _request_json(port, "GET", path)


async def _request_json(port: int, method: str, path: str):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(f"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".encode("ascii"))
    await writer.drain()
    data = await reader.read()
    writer.close()
    await writer.wait_closed()

    header, body = data.split(b"\r\n\r\n", 1)
    status = int(header.split(b" ", 2)[1])
    return status, json.loads(body)


class TestStatsServer:
    async def test_flow_stats_has_no_network_side_effects(self, echo_server):
        stats = FlowStats()
        server, task = await _start_server(addons=[stats])
        conn = None
        try:
            conn = await connect(Address(server.host, server.port), echo_server)
            conn.writer.write(b"flowstats")
            await conn.writer.drain()
            data = await conn.reader.read(4096)
            assert data == b"flowstats"

            payload = stats.snapshot()
            assert payload["active_flows"] == 1
            assert payload["active_bytes_up"] == 9
            assert payload["active_bytes_down"] == 9
            assert payload["active"][0]["started_at"].endswith("Z")
        finally:
            if conn is not None:
                conn.writer.close()
                await conn.writer.wait_closed()
            await _stop_server(server, task)

    async def test_health_endpoint(self):
        stats = StatsAPI()
        server, task = await _start_server(addons=[stats])
        try:
            status, payload = await _get_json(stats.port, "/health")
            assert status == 200
            assert payload == {"ok": True}
        finally:
            await _stop_server(server, task)

    async def test_stats_api_can_present_external_flow_stats_without_double_counting(
        self,
        echo_server,
    ):
        stats = FlowStats()
        api = StatsAPI(stats=stats)
        server, task = await _start_server(addons=[stats, api])
        conn = None
        try:
            conn = await connect(Address(server.host, server.port), echo_server)
            conn.writer.write(b"external")
            await conn.writer.drain()
            data = await conn.reader.read(4096)
            assert data == b"external"

            status, payload = await _get_json(api.port, "/stats")
            assert status == 200
            assert payload["total_flows"] == 1
            assert stats.snapshot()["total_flows"] == 1
        finally:
            if conn is not None:
                conn.writer.close()
                await conn.writer.wait_closed()
            await _stop_server(server, task)

    async def test_errors_endpoint(self):
        stats = StatsAPI()
        await stats.on_error(RuntimeError("boom"))
        server, task = await _start_server(addons=[stats])
        try:
            status, payload = await _get_json(stats.port, "/errors")
            assert status == 200
            assert payload["total"] == 1
            assert payload["by_type"] == {"RuntimeError": 1}
            assert payload["recent"][0]["message"] == "boom"
        finally:
            await _stop_server(server, task)

    async def test_flow_audit_has_no_network_side_effects(self, echo_server):
        audit = FlowAudit()
        server, task = await _start_server(addons=[audit])
        conn = None
        try:
            conn = await connect(Address(server.host, server.port), echo_server)
            conn.writer.write(b"audit")
            await conn.writer.drain()
            data = await conn.reader.read(4096)
            assert data == b"audit"
            conn.writer.close()
            await conn.writer.wait_closed()
            await asyncio.sleep(0.05)

            payload = audit.snapshot()
            assert payload["status"] == "ready"
            assert payload["records"] == 1
            assert payload["total"] == {"upload": 5, "download": 5, "total": 10}
            assert payload["devices"][0]["total"] == 10
            assert payload["traffic"][0]["total"] == 10
            assert payload["recent"][0]["started_at"].endswith("Z")
        finally:
            if conn is not None and not conn.writer.is_closing():
                conn.writer.close()
                await conn.writer.wait_closed()
            await _stop_server(server, task)

    async def test_stats_api_exposes_flow_audit(self, echo_server):
        audit = FlowAudit()
        api = StatsAPI(audit=audit)
        server, task = await _start_server(addons=[audit, api])
        conn = None
        try:
            conn = await connect(Address(server.host, server.port), echo_server)
            conn.writer.write(b"audit-api")
            await conn.writer.drain()
            data = await conn.reader.read(4096)
            assert data == b"audit-api"
            conn.writer.close()
            await conn.writer.wait_closed()
            await asyncio.sleep(0.05)

            status, payload = await _get_json(api.port, "/audit?top=1")
            assert status == 200
            assert payload["records"] == 1
            assert len(payload["devices"]) == 1
            assert len(payload["traffic"]) == 1

            status, payload = await _request_json(api.port, "POST", "/audit/refresh")
            assert status == 200
            assert payload["records"] == 1
        finally:
            if conn is not None and not conn.writer.is_closing():
                conn.writer.close()
                await conn.writer.wait_closed()
            await _stop_server(server, task)

    async def test_stats_api_reports_audit_disabled(self):
        stats = StatsAPI()
        server, task = await _start_server(addons=[stats])
        try:
            status, payload = await _get_json(stats.port, "/audit")
            assert status == 404
            assert payload == {"error": "audit disabled"}
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
            assert payload["started_at"].endswith("Z")
            assert payload["active_flows"] == 1
            assert payload["closed_flows"] == 0
            assert payload["total_closed_flows"] == 0
            assert payload["total_flows"] == 1
            assert payload["total_tcp_flows"] == 1
            assert payload["active_bytes_up"] == 5
            assert payload["active_bytes_down"] == 5
            assert payload["total_bytes_up"] == 5
            assert payload["total_bytes_down"] == 5
            assert payload["upload_rate"] >= 0
            assert payload["download_rate"] >= 0
            assert payload["errors"] == {"total": 0, "by_type": {}, "recent": []}
            assert payload["active"][0]["started_at"].endswith("Z")
            assert payload["active"][0]["bytes_up"] == 5
            assert payload["active"][0]["bytes_down"] == 5
            assert payload["active"][0]["upload_rate"] >= 0
            assert payload["active"][0]["download_rate"] >= 0

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
            assert snapshot["total_closed_flows"] == 1
            assert snapshot["closed_bytes_up"] == 5
            assert snapshot["closed_bytes_down"] == 5
            assert snapshot["total_bytes_up"] == 5
            assert snapshot["total_bytes_down"] == 5
        finally:
            await _stop_server(server, task)

    async def test_tracks_errors(self):
        stats = StatsServer()
        await stats.on_error(RuntimeError("boom"))

        snapshot = stats.snapshot()
        assert snapshot["errors"]["total"] == 1
        assert snapshot["errors"]["by_type"] == {"RuntimeError": 1}
        assert snapshot["errors"]["recent"][0]["type"] == "RuntimeError"
        assert snapshot["errors"]["recent"][0]["message"] == "boom"

    async def test_not_found(self):
        stats = StatsServer()
        server, task = await _start_server(addons=[stats])
        try:
            status, payload = await _get_json(stats.port, "/missing")
            assert status == 404
            assert payload == {"error": "not found"}
        finally:
            await _stop_server(server, task)
