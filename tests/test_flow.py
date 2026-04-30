"""Flow context tests: on_flow_close, bytes accuracy, dataclass, UdpRelay injection."""

import asyncio
import time

from asyncio_socks_server.addons.base import Addon
from asyncio_socks_server.addons.manager import AddonManager
from asyncio_socks_server.core.protocol import build_udp_header
from asyncio_socks_server.core.types import Address, Direction, Flow
from asyncio_socks_server.server.tcp_relay import _copy, handle_tcp_relay
from asyncio_socks_server.server.udp_relay import UdpRelay


def _make_flow(**kwargs):
    defaults = dict(
        id=1,
        src=Address("127.0.0.1", 1000),
        dst=Address("127.0.0.1", 2000),
        protocol="tcp",
        started_at=0.0,
    )
    defaults.update(kwargs)
    return Flow(**defaults)


# --- Flow dataclass tests ---


class TestFlowDataclass:
    def test_construction_with_defaults(self):
        flow = Flow(
            id=42,
            src=Address("10.0.0.1", 1234),
            dst=Address("10.0.0.2", 5678),
            protocol="tcp",
            started_at=100.0,
        )
        assert flow.id == 42
        assert flow.src.host == "10.0.0.1"
        assert flow.bytes_up == 0
        assert flow.bytes_down == 0

    def test_mutable_bytes(self):
        flow = _make_flow()
        flow.bytes_up += 100
        flow.bytes_down += 200
        assert flow.bytes_up == 100
        assert flow.bytes_down == 200

    def test_protocol_literal(self):
        flow_tcp = _make_flow(protocol="tcp")
        flow_udp = _make_flow(protocol="udp")
        assert flow_tcp.protocol == "tcp"
        assert flow_udp.protocol == "udp"

    def test_started_at_monotonic(self):
        before = time.monotonic()
        flow = Flow(
            id=1,
            src=Address("::", 0),
            dst=Address("::", 0),
            protocol="tcp",
            started_at=time.monotonic(),
        )
        after = time.monotonic()
        assert before <= flow.started_at <= after


# --- on_flow_close hook tests ---


class CloseCapture(Addon):
    def __init__(self):
        self.closed_flows: list[Flow] = []

    async def on_flow_close(self, flow):
        self.closed_flows.append(flow)


class CloseCrasher(Addon):
    async def on_flow_close(self, flow):
        raise RuntimeError("crash in on_flow_close")


class TestOnFlowClose:
    async def test_called_for_all_addons(self):
        a1 = CloseCapture()
        a2 = CloseCapture()
        mgr = AddonManager([a1, a2])
        flow = _make_flow()
        await mgr.dispatch_flow_close(flow)
        assert len(a1.closed_flows) == 1
        assert len(a2.closed_flows) == 1
        assert a1.closed_flows[0] is flow

    async def test_exception_does_not_propagate(self):
        a1 = CloseCrasher()
        a2 = CloseCapture()
        mgr = AddonManager([a1, a2])
        flow = _make_flow()
        await mgr.dispatch_flow_close(flow)
        assert len(a2.closed_flows) == 1

    async def test_receives_final_flow_snapshot(self):
        capture = CloseCapture()
        mgr = AddonManager([capture])
        flow = _make_flow()
        flow.bytes_up = 1024
        flow.bytes_down = 2048
        await mgr.dispatch_flow_close(flow)
        assert capture.closed_flows[0].bytes_up == 1024
        assert capture.closed_flows[0].bytes_down == 2048

    async def test_base_addon_skipped(self):
        mgr = AddonManager([Addon()])
        await mgr.dispatch_flow_close(_make_flow())

    async def test_no_addons(self):
        mgr = AddonManager([])
        await mgr.dispatch_flow_close(_make_flow())


# --- flow.bytes accuracy for TCP path ---


class TestTcpFlowBytes:
    async def _pipe(self):
        """Create a pipe: write to [0] → read from [3]. Keep all refs."""
        import socket

        sock_a, sock_b = socket.socketpair()
        sock_a.setblocking(False)
        sock_b.setblocking(False)
        reader_a, writer_a = await asyncio.open_connection(sock=sock_a)
        reader_b, writer_b = await asyncio.open_connection(sock=sock_b)
        return writer_a, writer_b, reader_a, reader_b

    async def test_copy_updates_bytes_up(self):
        in_wa, _in_wb, _in_ra, in_rb = await self._pipe()
        out_wa, _out_wb, _out_ra, out_rb = await self._pipe()

        flow = _make_flow()
        mgr = AddonManager()
        task = asyncio.create_task(_copy(in_rb, out_wa, mgr, Direction.UPSTREAM, flow))

        in_wa.write(b"hello")
        await in_wa.drain()
        data = await asyncio.wait_for(out_rb.read(4096), timeout=1.0)
        assert data == b"hello"

        in_wa.close()
        await in_wa.wait_closed()
        await asyncio.wait_for(task, timeout=1.0)

        assert flow.bytes_up == 5
        assert flow.bytes_down == 0

    async def test_copy_updates_bytes_down(self):
        in_wa, _in_wb, _in_ra, in_rb = await self._pipe()
        out_wa, _out_wb, _out_ra, out_rb = await self._pipe()

        flow = _make_flow()
        mgr = AddonManager()
        task = asyncio.create_task(
            _copy(in_rb, out_wa, mgr, Direction.DOWNSTREAM, flow)
        )

        in_wa.write(b"world")
        await in_wa.drain()
        data = await asyncio.wait_for(out_rb.read(4096), timeout=1.0)
        assert data == b"world"

        in_wa.close()
        await in_wa.wait_closed()
        await asyncio.wait_for(task, timeout=1.0)

        assert flow.bytes_up == 0
        assert flow.bytes_down == 5

    async def test_bidirectional_relay_bytes(self):
        import socket

        # Client pipe
        c_a, c_b = socket.socketpair()
        c_a.setblocking(False)
        c_b.setblocking(False)
        cr_app, cw_app = await asyncio.open_connection(sock=c_a)
        cr_relay, cw_relay = await asyncio.open_connection(sock=c_b)

        # Remote pipe
        r_a, r_b = socket.socketpair()
        r_a.setblocking(False)
        r_b.setblocking(False)
        rr_app, rw_app = await asyncio.open_connection(sock=r_a)
        rr_relay, rw_relay = await asyncio.open_connection(sock=r_b)

        flow = _make_flow()
        mgr = AddonManager()

        relay_task = asyncio.create_task(
            handle_tcp_relay(cr_relay, cw_relay, rr_relay, rw_relay, mgr, flow)
        )

        cw_app.write(b"abc")
        await cw_app.drain()
        data = await asyncio.wait_for(rr_app.read(4096), timeout=1.0)
        assert data == b"abc"

        rw_app.write(b"xyz")
        await rw_app.drain()
        data = await asyncio.wait_for(cr_app.read(4096), timeout=1.0)
        assert data == b"xyz"

        cw_app.close()
        await cw_app.wait_closed()
        rw_app.close()
        await rw_app.wait_closed()
        await asyncio.wait_for(relay_task, timeout=2.0)

        assert flow.bytes_up == 3
        assert flow.bytes_down == 3


# --- UdpRelay constructor injection tests ---


class TestUdpRelayFlowInjection:
    async def test_constructor_stores_flow(self):
        flow = _make_flow(protocol="udp")
        relay = UdpRelay(client_addr=Address("127.0.0.1", 12345), flow=flow)
        assert relay._flow is flow

    async def test_udp_bytes_single_write(self, udp_echo_server):
        echo_addr, _ = udp_echo_server
        flow = _make_flow(protocol="udp")
        relay = UdpRelay(client_addr=Address("127.0.0.1", 12345), flow=flow)
        try:
            await relay.start()

            datagram = build_udp_header(echo_addr) + b"hello"
            relay.handle_client_datagram(datagram, ("127.0.0.1", 12345))

            await asyncio.sleep(0.1)

            assert flow.bytes_up == 5
        finally:
            await relay.stop()
