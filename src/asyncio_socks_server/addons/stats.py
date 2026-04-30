from __future__ import annotations

import asyncio
import json
import time
from collections import deque
from dataclasses import asdict
from typing import Any

from asyncio_socks_server.addons.base import Addon
from asyncio_socks_server.core.types import Flow


class StatsServer(Addon):
    """Small HTTP stats server backed by live Flow objects.

    The server exposes JSON endpoints:
    - GET /health: liveness response
    - GET /stats: aggregate counters and active flow snapshots
    - GET /flows: active and recent closed flow snapshots

    Put this addon early in the addon list so competitive hooks can observe
    flows before another addon wins.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        max_closed_flows: int = 100,
    ) -> None:
        self.host = host
        self.port = port
        self.max_closed_flows = max_closed_flows
        self._server: asyncio.AbstractServer | None = None
        self._started_at = time.monotonic()
        self._active: dict[int, Flow] = {}
        self._seen_flow_ids: set[int] = set()
        self._closed: deque[dict[str, Any]] = deque(maxlen=max_closed_flows)
        self.total_flows = 0
        self.total_tcp_flows = 0
        self.total_udp_flows = 0
        self.total_bytes_up = 0
        self.total_bytes_down = 0

    async def on_start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_http,
            self.host,
            self.port,
        )
        sock = self._server.sockets[0] if self._server.sockets else None
        if sock is not None:
            self.port = sock.getsockname()[1]

    async def on_stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None

    async def on_connect(self, flow: Flow) -> None:
        self._track_flow(flow)

    async def on_udp_associate(self, flow: Flow) -> None:
        self._track_flow(flow)

    async def on_flow_close(self, flow: Flow) -> None:
        if flow.id not in self._seen_flow_ids:
            self._track_flow(flow)
        self._active.pop(flow.id, None)
        self._closed.append(self._flow_snapshot(flow, state="closed"))
        self.total_bytes_up += flow.bytes_up
        self.total_bytes_down += flow.bytes_down

    def snapshot(self) -> dict[str, Any]:
        """Return the same aggregate payload served by GET /stats."""
        return {
            "uptime_seconds": self._duration(self._started_at),
            "active_flows": len(self._active),
            "closed_flows": len(self._closed),
            "total_flows": self.total_flows,
            "total_tcp_flows": self.total_tcp_flows,
            "total_udp_flows": self.total_udp_flows,
            "total_bytes_up": self.total_bytes_up,
            "total_bytes_down": self.total_bytes_down,
            "active": [
                self._flow_snapshot(flow, state="active")
                for flow in self._active.values()
            ],
        }

    async def _handle_http(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            line = await reader.readline()
            method, path, _ = line.decode("ascii", errors="replace").split(" ", 2)
            while True:
                header = await reader.readline()
                if header in (b"\r\n", b"\n", b""):
                    break

            if method != "GET":
                await self._write_json(writer, 405, {"error": "method not allowed"})
            elif path == "/health":
                await self._write_json(writer, 200, {"ok": True})
            elif path == "/stats":
                await self._write_json(writer, 200, self.snapshot())
            elif path == "/flows":
                await self._write_json(
                    writer,
                    200,
                    {
                        "active": [
                            self._flow_snapshot(flow, state="active")
                            for flow in self._active.values()
                        ],
                        "recent_closed": list(self._closed),
                    },
                )
            else:
                await self._write_json(writer, 404, {"error": "not found"})
        except (ConnectionError, OSError, ValueError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    async def _write_json(
        self,
        writer: asyncio.StreamWriter,
        status: int,
        payload: dict[str, Any],
    ) -> None:
        reason = {
            200: "OK",
            404: "Not Found",
            405: "Method Not Allowed",
        }.get(status, "Error")
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        writer.write(
            f"HTTP/1.1 {status} {reason}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n".encode("ascii")
            + body
        )
        await writer.drain()

    def _track_flow(self, flow: Flow) -> None:
        self._active[flow.id] = flow
        if flow.id in self._seen_flow_ids:
            return
        self._seen_flow_ids.add(flow.id)
        self.total_flows += 1
        if flow.protocol == "tcp":
            self.total_tcp_flows += 1
        else:
            self.total_udp_flows += 1

    def _flow_snapshot(self, flow: Flow, state: str) -> dict[str, Any]:
        return {
            "id": flow.id,
            "state": state,
            "src": asdict(flow.src),
            "dst": asdict(flow.dst),
            "protocol": flow.protocol,
            "age_seconds": self._duration(flow.started_at),
            "bytes_up": flow.bytes_up,
            "bytes_down": flow.bytes_down,
        }

    @staticmethod
    def _duration(started_at: float) -> float:
        return round(time.monotonic() - started_at, 6)
