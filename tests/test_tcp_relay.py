"""Unit tests for TCP relay: _copy() and handle_tcp_relay()."""

import asyncio
import socket

import pytest

from asyncio_socks_server.addons.base import Addon
from asyncio_socks_server.addons.manager import AddonManager
from asyncio_socks_server.core.types import Address, Direction, Flow
from asyncio_socks_server.server.tcp_relay import _copy, handle_tcp_relay


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


async def _pipe():
    """Create a pipe with two ends.

    Returns (write_end, read_end):
      - Write to write_end → data appears on read_end.
    """
    sock_a, sock_b = socket.socketpair()
    sock_a.setblocking(False)
    sock_b.setblocking(False)
    # writer_a writes to sock_a → reader_b reads from sock_b
    reader_a, writer_a = await asyncio.open_connection(sock=sock_a)
    reader_b, writer_b = await asyncio.open_connection(sock=sock_b)
    # writer_a → reader_b is our pipe direction
    return (writer_a, writer_b, reader_a, reader_b)


class UpperAddon(Addon):
    async def on_data(self, direction, data, flow):
        return data.upper()


class DropAddon(Addon):
    async def on_data(self, direction, data, flow):
        return None


class TestCopy:
    async def test_copies_data(self):
        # Input: app writes → _copy reads
        in_wa, in_wb, in_ra, in_rb = await _pipe()  # in_wa → in_rb
        # Output: _copy writes → app reads
        out_wa, out_wb, out_ra, out_rb = await _pipe()  # out_wa → out_rb

        flow = _make_flow()
        manager = AddonManager()
        copy_task = asyncio.create_task(
            _copy(in_rb, out_wa, manager, Direction.UPSTREAM, flow)
        )

        in_wa.write(b"hello")
        await in_wa.drain()
        data = await asyncio.wait_for(out_rb.read(4096), timeout=1.0)
        assert data == b"hello"

        in_wa.close()
        await in_wa.wait_closed()
        await asyncio.wait_for(copy_task, timeout=2.0)

    async def test_stops_on_eof(self):
        in_wa, in_wb, in_ra, in_rb = await _pipe()
        out_wa, out_wb, out_ra, out_rb = await _pipe()

        flow = _make_flow()
        manager = AddonManager()
        in_wa.close()
        await in_wa.wait_closed()

        copy_task = asyncio.create_task(
            _copy(in_rb, out_wa, manager, Direction.UPSTREAM, flow)
        )
        await asyncio.wait_for(copy_task, timeout=1.0)

    async def test_addon_pipeline_applied(self):
        in_wa, in_wb, in_ra, in_rb = await _pipe()
        out_wa, out_wb, out_ra, out_rb = await _pipe()

        flow = _make_flow()
        manager = AddonManager([UpperAddon()])
        copy_task = asyncio.create_task(
            _copy(in_rb, out_wa, manager, Direction.UPSTREAM, flow)
        )

        in_wa.write(b"hello")
        await in_wa.drain()
        data = await asyncio.wait_for(out_rb.read(4096), timeout=1.0)
        assert data == b"HELLO"

        in_wa.close()
        await in_wa.wait_closed()
        await asyncio.wait_for(copy_task, timeout=2.0)

    async def test_addon_returns_none_skips_write(self):
        in_wa, in_wb, in_ra, in_rb = await _pipe()
        out_wa, out_wb, out_ra, out_rb = await _pipe()

        flow = _make_flow()
        manager = AddonManager([DropAddon()])
        copy_task = asyncio.create_task(
            _copy(in_rb, out_wa, manager, Direction.UPSTREAM, flow)
        )

        in_wa.write(b"dropped")
        await in_wa.drain()

        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(out_rb.read(4096), timeout=0.3)

        in_wa.close()
        await in_wa.wait_closed()
        await asyncio.wait_for(copy_task, timeout=2.0)

    async def test_connection_error_handled(self):
        in_wa, in_wb, in_ra, in_rb = await _pipe()
        out_wa, out_wb, out_ra, out_rb = await _pipe()

        flow = _make_flow()
        manager = AddonManager()
        out_wa.close()
        await out_wa.wait_closed()

        copy_task = asyncio.create_task(
            _copy(in_rb, out_wa, manager, Direction.UPSTREAM, flow)
        )

        in_wa.write(b"trigger")
        await in_wa.drain()

        await asyncio.wait_for(copy_task, timeout=2.0)
        in_wa.close()
        await in_wa.wait_closed()

    async def test_writer_closed_on_finish(self):
        in_wa, in_wb, in_ra, in_rb = await _pipe()
        out_wa, out_wb, out_ra, out_rb = await _pipe()

        flow = _make_flow()
        manager = AddonManager()
        in_wa.close()
        await in_wa.wait_closed()

        await _copy(in_rb, out_wa, manager, Direction.UPSTREAM, flow)
        assert out_wa.is_closing()


class TestHandleTcpRelay:
    async def test_bidirectional_relay(self):
        # Client pipe: cw_app → cr_relay, cw_relay → cr_app
        c_sock_a, c_sock_b = socket.socketpair()
        c_sock_a.setblocking(False)
        c_sock_b.setblocking(False)
        cr_app, cw_app = await asyncio.open_connection(sock=c_sock_a)
        cr_relay, cw_relay = await asyncio.open_connection(sock=c_sock_b)

        # Remote pipe: rw_app → rr_relay, rw_relay → rr_app
        r_sock_a, r_sock_b = socket.socketpair()
        r_sock_a.setblocking(False)
        r_sock_b.setblocking(False)
        rr_app, rw_app = await asyncio.open_connection(sock=r_sock_a)
        rr_relay, rw_relay = await asyncio.open_connection(sock=r_sock_b)

        flow = _make_flow()
        manager = AddonManager()

        relay_task = asyncio.create_task(
            handle_tcp_relay(cr_relay, cw_relay, rr_relay, rw_relay, manager, flow)
        )

        # Client → Remote
        cw_app.write(b"to-remote")
        await cw_app.drain()
        data = await asyncio.wait_for(rr_app.read(4096), timeout=1.0)
        assert data == b"to-remote"

        # Remote → Client
        rw_app.write(b"to-client")
        await rw_app.drain()
        data = await asyncio.wait_for(cr_app.read(4096), timeout=1.0)
        assert data == b"to-client"

        cw_app.close()
        await cw_app.wait_closed()
        rw_app.close()
        await rw_app.wait_closed()
        await asyncio.wait_for(relay_task, timeout=2.0)

    async def test_relay_stops_when_client_closes(self):
        c_sock_a, c_sock_b = socket.socketpair()
        c_sock_a.setblocking(False)
        c_sock_b.setblocking(False)
        cr_app, cw_app = await asyncio.open_connection(sock=c_sock_a)
        cr_relay, cw_relay = await asyncio.open_connection(sock=c_sock_b)

        r_sock_a, r_sock_b = socket.socketpair()
        r_sock_a.setblocking(False)
        r_sock_b.setblocking(False)
        rr_app, rw_app = await asyncio.open_connection(sock=r_sock_a)
        rr_relay, rw_relay = await asyncio.open_connection(sock=r_sock_b)

        flow = _make_flow()
        manager = AddonManager()

        relay_task = asyncio.create_task(
            handle_tcp_relay(cr_relay, cw_relay, rr_relay, rw_relay, manager, flow)
        )

        cw_app.close()
        await cw_app.wait_closed()
        await asyncio.wait_for(relay_task, timeout=2.0)
