from __future__ import annotations

import asyncio
import json
import time
from collections import deque
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any

from asyncio_socks_server.addons.base import Addon
from asyncio_socks_server.core.types import Flow


class FlowStats(Addon):
    """Flow statistics collector with no network side effects.

    FlowStats is the reusable stats infrastructure. It implements addon hooks,
    keeps in-memory flow counters, and exposes plain Python snapshot methods.
    Applications can attach their own HTTP API, metrics exporter, file writer,
    or any other presentation layer around it.
    """

    def __init__(
        self,
        max_closed_flows: int = 100,
        max_recent_errors: int = 50,
    ) -> None:
        self.max_closed_flows = max_closed_flows
        self.max_recent_errors = max_recent_errors
        self._started_at = time.monotonic()
        self._started_wall_at = time.time()
        self._active: dict[int, Flow] = {}
        self._seen_flow_ids: set[int] = set()
        self._closed: deque[dict[str, Any]] = deque(maxlen=max_closed_flows)
        self._recent_errors: deque[dict[str, Any]] = deque(maxlen=max_recent_errors)
        self.total_flows = 0
        self.total_tcp_flows = 0
        self.total_udp_flows = 0
        self.total_closed_flows = 0
        self.closed_bytes_up = 0
        self.closed_bytes_down = 0
        self.total_errors = 0
        self.errors_by_type: dict[str, int] = {}
        self._last_total_sample_at = self._started_at
        self._last_total_bytes_up = 0
        self._last_total_bytes_down = 0
        self._upload_rate = 0.0
        self._download_rate = 0.0
        self._flow_rates: dict[int, dict[str, float]] = {}

    async def on_connect(self, flow: Flow) -> None:
        self._track_flow(flow)

    async def on_udp_associate(self, flow: Flow) -> None:
        self._track_flow(flow)

    async def on_flow_close(self, flow: Flow) -> None:
        if flow.id not in self._seen_flow_ids:
            self._track_flow(flow)
        self._sample_flow_rate(flow)
        self._active.pop(flow.id, None)
        self._closed.append(self._flow_snapshot(flow, state="closed"))
        self.total_closed_flows += 1
        self.closed_bytes_up += flow.bytes_up
        self.closed_bytes_down += flow.bytes_down
        self._flow_rates.pop(flow.id, None)

    async def on_error(self, error: Exception) -> None:
        name = type(error).__name__
        self.total_errors += 1
        self.errors_by_type[name] = self.errors_by_type.get(name, 0) + 1
        self._recent_errors.append(
            {
                "type": name,
                "message": str(error),
                "at": self._format_wall_time(time.time()),
            }
        )

    def snapshot(self) -> dict[str, Any]:
        """Return aggregate counters plus active flow snapshots."""
        self._sample_rates()
        active_bytes_up = sum(flow.bytes_up for flow in self._active.values())
        active_bytes_down = sum(flow.bytes_down for flow in self._active.values())
        return {
            "started_at": self._format_wall_time(self._started_wall_at),
            "uptime_seconds": self._duration(self._started_at),
            "active_flows": len(self._active),
            "closed_flows": len(self._closed),
            "recent_closed_flows": len(self._closed),
            "total_closed_flows": self.total_closed_flows,
            "total_flows": self.total_flows,
            "total_tcp_flows": self.total_tcp_flows,
            "total_udp_flows": self.total_udp_flows,
            "active_bytes_up": active_bytes_up,
            "active_bytes_down": active_bytes_down,
            "closed_bytes_up": self.closed_bytes_up,
            "closed_bytes_down": self.closed_bytes_down,
            "total_bytes_up": self.closed_bytes_up + active_bytes_up,
            "total_bytes_down": self.closed_bytes_down + active_bytes_down,
            "upload_rate": self._upload_rate,
            "download_rate": self._download_rate,
            "errors": self.errors(),
            "active": self._active_flow_snapshots(),
        }

    def active_flows(self) -> list[dict[str, Any]]:
        """Return active flow snapshots."""
        self._sample_rates()
        return self._active_flow_snapshots()

    def _active_flow_snapshots(self) -> list[dict[str, Any]]:
        return [
            self._flow_snapshot(flow, state="active") for flow in self._active.values()
        ]

    def recent_closed_flows(self) -> list[dict[str, Any]]:
        """Return retained closed flow snapshots."""
        return list(self._closed)

    def flows(self) -> dict[str, Any]:
        """Return active and retained closed flow snapshots."""
        return {
            "active": self.active_flows(),
            "recent_closed": self.recent_closed_flows(),
        }

    def errors(self) -> dict[str, Any]:
        """Return error counters observed through on_error."""
        return {
            "total": self.total_errors,
            "by_type": dict(sorted(self.errors_by_type.items())),
            "recent": list(self._recent_errors),
        }

    def _track_flow(self, flow: Flow) -> None:
        self._active[flow.id] = flow
        if flow.id in self._seen_flow_ids:
            return
        self._seen_flow_ids.add(flow.id)
        self._flow_rates[flow.id] = {
            "sample_at": time.monotonic(),
            "bytes_up": float(flow.bytes_up),
            "bytes_down": float(flow.bytes_down),
            "upload_rate": 0.0,
            "download_rate": 0.0,
        }
        self.total_flows += 1
        if flow.protocol == "tcp":
            self.total_tcp_flows += 1
        else:
            self.total_udp_flows += 1

    def _flow_snapshot(self, flow: Flow, state: str) -> dict[str, Any]:
        rates = self._flow_rates.get(flow.id, {})
        return {
            "id": flow.id,
            "state": state,
            "src": asdict(flow.src),
            "dst": asdict(flow.dst),
            "protocol": flow.protocol,
            "started_at": self._format_wall_time(flow.started_wall_at),
            "age_seconds": self._duration(flow.started_at),
            "bytes_up": flow.bytes_up,
            "bytes_down": flow.bytes_down,
            "upload_rate": rates.get("upload_rate", 0.0),
            "download_rate": rates.get("download_rate", 0.0),
        }

    def _sample_rates(self) -> None:
        for flow in self._active.values():
            self._sample_flow_rate(flow)

        now = time.monotonic()
        active_bytes_up = sum(flow.bytes_up for flow in self._active.values())
        active_bytes_down = sum(flow.bytes_down for flow in self._active.values())
        total_bytes_up = self.closed_bytes_up + active_bytes_up
        total_bytes_down = self.closed_bytes_down + active_bytes_down
        elapsed = now - self._last_total_sample_at
        if elapsed > 0:
            self._upload_rate = (total_bytes_up - self._last_total_bytes_up) / elapsed
            self._download_rate = (
                total_bytes_down - self._last_total_bytes_down
            ) / elapsed
        self._last_total_sample_at = now
        self._last_total_bytes_up = total_bytes_up
        self._last_total_bytes_down = total_bytes_down

    def _sample_flow_rate(self, flow: Flow) -> None:
        now = time.monotonic()
        sample = self._flow_rates.setdefault(
            flow.id,
            {
                "sample_at": now,
                "bytes_up": float(flow.bytes_up),
                "bytes_down": float(flow.bytes_down),
                "upload_rate": 0.0,
                "download_rate": 0.0,
            },
        )
        elapsed = now - sample["sample_at"]
        if elapsed > 0:
            sample["upload_rate"] = (flow.bytes_up - sample["bytes_up"]) / elapsed
            sample["download_rate"] = (flow.bytes_down - sample["bytes_down"]) / elapsed
        sample["sample_at"] = now
        sample["bytes_up"] = float(flow.bytes_up)
        sample["bytes_down"] = float(flow.bytes_down)

    @staticmethod
    def _format_wall_time(timestamp: float) -> str:
        return datetime.fromtimestamp(timestamp, UTC).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _duration(started_at: float) -> float:
        return round(time.monotonic() - started_at, 6)


class StatsAPI(Addon):
    """Opt-in HTTP API backed by FlowStats.

    StatsAPI starts an HTTP listener only when explicitly added to a Server.
    When constructed without a FlowStats instance, it owns one and forwards flow
    hooks into it. When constructed with an existing FlowStats instance, it acts
    only as a presentation layer so applications can compose both addons without
    double-counting flows.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        max_closed_flows: int = 100,
        stats: FlowStats | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.max_closed_flows = max_closed_flows
        self.stats = stats or FlowStats(max_closed_flows=max_closed_flows)
        self._owns_stats = stats is None
        self._server: asyncio.AbstractServer | None = None

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
        if self._owns_stats:
            await self.stats.on_connect(flow)

    async def on_udp_associate(self, flow: Flow) -> None:
        if self._owns_stats:
            await self.stats.on_udp_associate(flow)

    async def on_flow_close(self, flow: Flow) -> None:
        if self._owns_stats:
            await self.stats.on_flow_close(flow)

    async def on_error(self, error: Exception) -> None:
        if self._owns_stats:
            await self.stats.on_error(error)

    def snapshot(self) -> dict[str, Any]:
        return self.stats.snapshot()

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
                await self._write_json(writer, 200, self.stats.snapshot())
            elif path == "/flows":
                await self._write_json(writer, 200, self.stats.flows())
            elif path == "/errors":
                await self._write_json(writer, 200, self.stats.errors())
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


class StatsServer(StatsAPI):
    """Backward-compatible name for StatsAPI."""
