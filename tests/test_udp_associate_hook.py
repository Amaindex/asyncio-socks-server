"""Tests for the on_udp_associate competitive hook."""

import asyncio

from asyncio_socks_server.addons.base import Addon
from asyncio_socks_server.core.types import Address
from asyncio_socks_server.server.server import Server
from asyncio_socks_server.server.udp_relay import UdpRelayBase


class _CustomRelay(UdpRelayBase):
    """Minimal UdpRelayBase that records calls."""

    def __init__(self):
        self.started = False
        self.stopped = False
        self.client_transport_set = False
        self.datagrams: list[bytes] = []

    async def start(self) -> Address:
        self.started = True
        return Address("127.0.0.1", 12345)

    def set_client_transport(self, transport: asyncio.DatagramTransport) -> None:
        self.client_transport_set = True

    async def stop(self) -> None:
        self.stopped = True

    def handle_client_datagram(self, data: bytes, client_addr: tuple[str, int]) -> None:
        self.datagrams.append(data)


class _CustomAddon(Addon):
    def __init__(self, relay: UdpRelayBase):
        self._relay = relay

    async def on_udp_associate(self, flow) -> UdpRelayBase | None:
        return self._relay


class _PassAddon(Addon):
    async def on_udp_associate(self, flow) -> UdpRelayBase | None:
        return None


class _FailingRelay(UdpRelayBase):
    def __init__(self):
        self.stopped = False

    async def start(self) -> Address:
        raise RuntimeError("udp relay failed")

    def set_client_transport(self, transport: asyncio.DatagramTransport) -> None:
        pass

    async def stop(self) -> None:
        self.stopped = True

    def handle_client_datagram(self, data: bytes, client_addr: tuple[str, int]) -> None:
        pass


class _ErrorTracker(Addon):
    def __init__(self):
        self.errors: list[Exception] = []

    async def on_error(self, error: Exception) -> None:
        self.errors.append(error)


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


class TestUdpAssociateHook:
    async def test_addon_returns_custom_handler(self):
        """Addon returning a custom UdpRelayBase replaces the default."""
        relay = _CustomRelay()
        addon = _CustomAddon(relay)
        server, task = await _start_server(addons=[addon])
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
            # SOCKS5 handshake
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            resp = await reader.readexactly(2)
            assert resp == b"\x05\x00"
            # UDP ASSOCIATE
            writer.write(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            # Read reply
            reply = await reader.readexactly(3)
            assert reply[0] == 0x05
            # reply[1] == 0x00 means success (custom relay returned its addr)
            # Read bound address
            atyp = (await reader.readexactly(1))[0]
            if atyp == 0x01:
                await reader.readexactly(4 + 2)
            elif atyp == 0x04:
                await reader.readexactly(16 + 2)
            assert relay.started
            writer.close()
            await writer.wait_closed()
        finally:
            await _stop_server(server, task)

    async def test_addon_returns_none_uses_default(self):
        """Addon returning None falls through to default UdpRelay."""
        addon = _PassAddon()
        server, task = await _start_server(addons=[addon])
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            resp = await reader.readexactly(2)
            assert resp == b"\x05\x00"
            writer.write(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            reply = await reader.readexactly(3)
            assert reply[0] == 0x05
            assert reply[1] == 0x00
            writer.close()
            await writer.wait_closed()
        finally:
            await _stop_server(server, task)

    async def test_competitive_first_wins(self):
        """Multiple addons: first non-None result wins."""
        relay_a = _CustomRelay()
        relay_b = _CustomRelay()

        class AddonA(Addon):
            async def on_udp_associate(self, flow):
                return relay_a

        class AddonB(Addon):
            async def on_udp_associate(self, flow):
                return relay_b

        server, task = await _start_server(addons=[AddonA(), AddonB()])
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            resp = await reader.readexactly(2)
            assert resp == b"\x05\x00"
            writer.write(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            reply = await reader.readexactly(3)
            assert reply[1] == 0x00
            await reader.readexactly(1)  # atyp
            await reader.readexactly(4 + 2)  # ipv4+port
            assert relay_a.started
            assert not relay_b.started
            writer.close()
            await writer.wait_closed()
        finally:
            await _stop_server(server, task)

    async def test_relay_start_failure_returns_socks_error_and_dispatches_error(self):
        relay = _FailingRelay()
        tracker = _ErrorTracker()
        server, task = await _start_server(
            addons=[_CustomAddon(relay), tracker],
        )
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            resp = await reader.readexactly(2)
            assert resp == b"\x05\x00"

            writer.write(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()

            reply = await reader.readexactly(3)
            assert reply == b"\x05\x01\x00"
            atyp = await reader.readexactly(1)
            assert atyp == b"\x01"
            await reader.readexactly(4 + 2)

            assert relay.stopped
            assert len(tracker.errors) == 1
            assert isinstance(tracker.errors[0], RuntimeError)

            writer.close()
            await writer.wait_closed()
        finally:
            await _stop_server(server, task)
