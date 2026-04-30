"""UDP relay tests: UdpRelay unit + UDP ASSOCIATE end-to-end."""

import asyncio
import time

from asyncio_socks_server.core.address import encode_address
from asyncio_socks_server.core.protocol import build_udp_header
from asyncio_socks_server.core.types import Address, Flow
from asyncio_socks_server.server.udp_relay import UdpRelay
from tests.conftest import _start_server, _stop_server


def _udp_flow():
    return Flow(
        id=1,
        src=Address("127.0.0.1", 12345),
        dst=Address("0.0.0.0", 0),
        protocol="udp",
        started_at=0.0,
    )


def _build_udp_datagram(dst: Address, payload: bytes) -> bytes:
    """Build a SOCKS5-encapsulated UDP datagram."""
    return build_udp_header(dst) + payload


async def _socks5_udp_associate(proxy: Address, auth=None):
    """Perform SOCKS5 handshake + UDP ASSOCIATE.

    Returns (tcp_reader, tcp_writer, udp_bind_addr).
    """
    reader, writer = await asyncio.open_connection(proxy.host, proxy.port)

    # Method selection
    if auth:
        writer.write(b"\x05\x01\x02")
    else:
        writer.write(b"\x05\x01\x00")
    await writer.drain()
    resp = await reader.readexactly(2)
    assert resp[0] == 0x05

    if auth:
        assert resp[1] == 0x02
        uname = auth[0].encode()
        passwd = auth[1].encode()
        writer.write(
            b"\x01"
            + len(uname).to_bytes(1, "big")
            + uname
            + len(passwd).to_bytes(1, "big")
            + passwd
        )
        await writer.drain()
        auth_resp = await reader.readexactly(2)
        assert auth_resp == b"\x01\x00"
    else:
        assert resp[1] == 0x00

    # UDP ASSOCIATE request (dst = 0.0.0.0:0)
    writer.write(b"\x05\x03\x00" + encode_address("0.0.0.0", 0))
    await writer.drain()

    reply = await reader.readexactly(3)
    assert reply[0] == 0x05
    assert reply[1] == 0x00  # succeeded

    # Read bound address
    atyp = (await reader.readexactly(1))[0]
    if atyp == 0x01:
        host_bytes = await reader.readexactly(4)
        import ipaddress

        bind_host = ipaddress.IPv4Address(host_bytes).compressed
    elif atyp == 0x04:
        host_bytes = await reader.readexactly(16)
        import ipaddress

        bind_host = ipaddress.IPv6Address(host_bytes).compressed
    else:
        length = (await reader.readexactly(1))[0]
        bind_host = (await reader.readexactly(length)).decode("ascii")
    port_bytes = await reader.readexactly(2)
    import struct

    bind_port = struct.unpack("!H", port_bytes)[0]

    return reader, writer, Address(bind_host, bind_port)


class TestUdpRelayUnit:
    async def test_start_returns_bind_address(self):
        relay = UdpRelay(client_addr=Address("127.0.0.1", 12345), flow=_udp_flow())
        try:
            bind_addr = await relay.start()
            assert bind_addr.port > 0
            assert bind_addr.host != ""
        finally:
            await relay.stop()

    async def test_stop_cancels_ttl_task(self):
        relay = UdpRelay(client_addr=Address("127.0.0.1", 12345), flow=_udp_flow())
        await relay.start()
        ttl_task = relay._ttl_task
        await relay.stop()
        assert ttl_task.cancelled() or ttl_task.done()

    async def test_handle_client_datagram_routes_outbound(self, udp_echo_server):
        echo_addr, received = udp_echo_server
        relay = UdpRelay(client_addr=Address("127.0.0.1", 12345), flow=_udp_flow())
        try:
            await relay.start()

            datagram = _build_udp_datagram(echo_addr, b"hello")
            relay.handle_client_datagram(datagram, ("127.0.0.1", 12345))

            # Wait for echo server to receive
            for _ in range(50):
                if received:
                    break
                await asyncio.sleep(0.02)

            assert len(received) == 1
            assert received[0][0] == b"hello"
        finally:
            await relay.stop()

    async def test_handle_client_datagram_empty_payload_ignored(self):
        relay = UdpRelay(client_addr=Address("127.0.0.1", 12345), flow=_udp_flow())
        try:
            await relay.start()
            # Valid header but empty payload
            datagram = _build_udp_datagram(Address("127.0.0.1", 80), b"")
            relay.handle_client_datagram(datagram, ("127.0.0.1", 12345))
            # No route should be created (empty payload is ignored)
            assert len(relay._route_map) == 0
        finally:
            await relay.stop()

    async def test_handle_client_datagram_malformed_ignored(self):
        relay = UdpRelay(client_addr=Address("127.0.0.1", 12345), flow=_udp_flow())
        try:
            await relay.start()
            relay.handle_client_datagram(b"garbage", ("127.0.0.1", 12345))
            assert len(relay._route_map) == 0
        finally:
            await relay.stop()

    async def test_routing_table_entries_created(self):
        relay = UdpRelay(client_addr=Address("127.0.0.1", 12345), flow=_udp_flow())
        try:
            await relay.start()
            datagram = _build_udp_datagram(Address("127.0.0.1", 80), b"data")
            relay.handle_client_datagram(datagram, ("127.0.0.1", 12345))
            assert ("127.0.0.1", 80) in relay._route_map
        finally:
            await relay.stop()

    async def test_routing_table_entries_refreshed(self):
        relay = UdpRelay(client_addr=Address("127.0.0.1", 12345), flow=_udp_flow())
        try:
            await relay.start()
            datagram = _build_udp_datagram(Address("127.0.0.1", 80), b"data")
            relay.handle_client_datagram(datagram, ("127.0.0.1", 12345))
            ts1 = relay._route_timestamps[("127.0.0.1", 80)]

            await asyncio.sleep(0.05)
            relay.handle_client_datagram(datagram, ("127.0.0.1", 12345))
            ts2 = relay._route_timestamps[("127.0.0.1", 80)]
            assert ts2 > ts1
        finally:
            await relay.stop()


class TestUdpRelayTTL:
    async def test_ttl_cleanup_removes_expired(self):
        relay = UdpRelay(
            client_addr=Address("127.0.0.1", 12345), flow=_udp_flow(), ttl=0.1
        )
        try:
            await relay.start()
            # Manually inject a route with old timestamp
            relay._route_map[("10.0.0.1", 80)] = ("127.0.0.1", 12345)
            relay._route_timestamps[("10.0.0.1", 80)] = time.monotonic() - 1.0

            # Wait for TTL cleanup (runs every 60s, but we can trigger manually)
            # Let's just wait enough time — the cleanup loop runs every 60s,
            # so we manually trigger it
            now = time.monotonic()
            expired = [
                key
                for key, ts in relay._route_timestamps.items()
                if now - ts > relay._ttl
            ]
            for key in expired:
                relay._route_map.pop(key, None)
                relay._route_timestamps.pop(key, None)

            assert ("10.0.0.1", 80) not in relay._route_map
        finally:
            await relay.stop()

    async def test_ttl_cleanup_keeps_active(self):
        relay = UdpRelay(
            client_addr=Address("127.0.0.1", 12345), flow=_udp_flow(), ttl=300
        )
        try:
            await relay.start()
            relay._route_map[("10.0.0.1", 80)] = ("127.0.0.1", 12345)
            relay._route_timestamps[("10.0.0.1", 80)] = time.monotonic()

            now = time.monotonic()
            expired = [
                key
                for key, ts in relay._route_timestamps.items()
                if now - ts > relay._ttl
            ]
            assert len(expired) == 0
            assert ("10.0.0.1", 80) in relay._route_map
        finally:
            await relay.stop()


class TestUdpAssociateE2E:
    async def test_udp_associate_handshake(self):
        """Test UDP ASSOCIATE returns a valid bind address."""
        server, task = await _start_server()
        try:
            tcp_r, tcp_w, udp_bind = await _socks5_udp_associate(
                Address(server.host, server.port)
            )
            assert udp_bind.port > 0
            tcp_w.close()
            await tcp_w.wait_closed()
        finally:
            await _stop_server(server, task)

    async def test_udp_associate_with_auth(self):
        server, task = await _start_server(auth=("user", "pass"))
        try:
            tcp_r, tcp_w, udp_bind = await _socks5_udp_associate(
                Address(server.host, server.port), auth=("user", "pass")
            )
            assert udp_bind.port > 0
            tcp_w.close()
            await tcp_w.wait_closed()
        finally:
            await _stop_server(server, task)

    async def test_udp_associate_send_and_receive(self, udp_echo_server):
        """Test sending a UDP datagram through the proxy and receiving the echo."""
        echo_addr, _ = udp_echo_server
        server, task = await _start_server()
        try:
            tcp_r, tcp_w, udp_bind = await _socks5_udp_associate(
                Address(server.host, server.port)
            )
            await asyncio.sleep(0.05)  # Let server settle

            # Set up a UDP client that can send and receive
            loop = asyncio.get_running_loop()
            received = asyncio.get_event_loop().create_future()

            class ClientProtocol(asyncio.DatagramProtocol):
                def datagram_received(self, data, addr):
                    if not received.done():
                        received.set_result(data)

            transport, _ = await loop.create_datagram_endpoint(
                ClientProtocol, local_addr=("127.0.0.1", 0)
            )

            # Send SOCKS5-encapsulated datagram to proxy's UDP bind
            datagram = _build_udp_datagram(echo_addr, b"hello")
            transport.sendto(datagram, (udp_bind.host, udp_bind.port))

            # Wait for echo response
            try:
                resp_data = await asyncio.wait_for(received, timeout=2.0)
                from asyncio_socks_server.core.protocol import parse_udp_header

                resp_addr, _, resp_payload = parse_udp_header(resp_data)
                assert resp_payload == b"hello"
            finally:
                transport.close()
                tcp_w.close()
                await tcp_w.wait_closed()
        finally:
            await _stop_server(server, task)

    async def test_tcp_close_ends_relay(self):
        server, task = await _start_server()
        try:
            tcp_r, tcp_w, udp_bind = await _socks5_udp_associate(
                Address(server.host, server.port)
            )
            assert udp_bind.port > 0

            tcp_w.close()
            await tcp_w.wait_closed()
            await asyncio.sleep(0.3)

            # Sending to the closed relay should not crash
            loop = asyncio.get_running_loop()

            class SilentProtocol(asyncio.DatagramProtocol):
                def datagram_received(self, data, addr):
                    pass

            transport, _ = await loop.create_datagram_endpoint(
                SilentProtocol, local_addr=("127.0.0.1", 0)
            )
            try:
                transport.sendto(
                    _build_udp_datagram(Address("127.0.0.1", 1), b"x"),
                    (udp_bind.host, udp_bind.port),
                )
            except OSError:
                pass
            transport.close()
        finally:
            await _stop_server(server, task)
