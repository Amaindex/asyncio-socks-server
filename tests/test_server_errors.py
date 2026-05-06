"""Server error handling tests: malformed input, disconnects, error mapping."""

import asyncio

from asyncio_socks_server import FlowStats
from asyncio_socks_server.core.types import Address, Rep
from asyncio_socks_server.server.server import Server
from tests.conftest import _start_server, _stop_server


async def _raw_connect(proxy):
    """Open a raw TCP connection to the proxy."""
    return await asyncio.open_connection(proxy.host, proxy.port)


async def _read_reply(reader):
    """Read a SOCKS5 CONNECT reply and return (rep_code, bound_addr)."""
    ver, rep, rsv = await reader.readexactly(3)
    atyp = (await reader.readexactly(1))[0]
    if atyp == 0x01:
        await reader.readexactly(4 + 2)
    elif atyp == 0x04:
        await reader.readexactly(16 + 2)
    elif atyp == 0x03:
        length = (await reader.readexactly(1))[0]
        await reader.readexactly(length + 2)
    return rep


class TestHandshakeErrors:
    async def test_truncated_method_selection(self):
        server, task = await _start_server()
        try:
            reader, writer = await _raw_connect(Address(server.host, server.port))
            writer.write(b"\x05")
            await writer.drain()
            # Server expects 2 bytes minimum; send 1 then close
            writer.close()
            await writer.wait_closed()
            # Server should handle this without crashing
            await asyncio.sleep(0.1)
        finally:
            await _stop_server(server, task)

    async def test_wrong_socks_version(self):
        server, task = await _start_server()
        try:
            reader, writer = await _raw_connect(Address(server.host, server.port))
            writer.write(b"\x04\x01\x00")
            await writer.drain()
            # Server should close or reject — just verify no crash
            writer.close()
            await writer.wait_closed()
        finally:
            await _stop_server(server, task)

    async def test_disconnect_after_method_reply(self):
        server, task = await _start_server()
        try:
            reader, writer = await _raw_connect(Address(server.host, server.port))
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            resp = await reader.readexactly(2)
            assert resp == b"\x05\x00"  # NO_AUTH selected
            # Now disconnect without sending a request
            writer.close()
            await writer.wait_closed()
            await asyncio.sleep(0.1)
        finally:
            await _stop_server(server, task)

    async def test_disconnect_during_auth(self):
        server, task = await _start_server(auth=("user", "pass"))
        try:
            reader, writer = await _raw_connect(Address(server.host, server.port))
            writer.write(b"\x05\x01\x02")
            await writer.drain()
            resp = await reader.readexactly(2)
            assert resp[1] == 0x02  # USERNAME_PASSWORD selected
            # Disconnect without sending credentials
            writer.close()
            await writer.wait_closed()
            await asyncio.sleep(0.1)
        finally:
            await _stop_server(server, task)

    async def test_nmethods_zero(self):
        server, task = await _start_server()
        try:
            reader, writer = await _raw_connect(Address(server.host, server.port))
            writer.write(b"\x05\x00")
            await writer.drain()
            resp = await reader.readexactly(2)
            assert resp[1] == 0xFF  # NO_ACCEPTABLE
            writer.close()
            await writer.wait_closed()
        finally:
            await _stop_server(server, task)


class TestRequestErrors:
    async def test_connect_to_refused_port(self):
        server, task = await _start_server()
        try:
            reader, writer = await _raw_connect(Address(server.host, server.port))
            # Method selection
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            resp = await reader.readexactly(2)
            assert resp[1] == 0x00

            # CONNECT to 127.0.0.1:1 (should refuse)
            writer.write(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x01")
            await writer.drain()

            rep = await _read_reply(reader)
            assert rep == Rep.CONNECTION_REFUSED
            writer.close()
            await writer.wait_closed()
        finally:
            await _stop_server(server, task)

    async def test_failed_connect_closes_observed_flow(self):
        stats = FlowStats()
        server, task = await _start_server(addons=[stats])
        try:
            reader, writer = await _raw_connect(Address(server.host, server.port))
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            resp = await reader.readexactly(2)
            assert resp[1] == 0x00

            writer.write(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x01")
            await writer.drain()

            rep = await _read_reply(reader)
            assert rep == Rep.CONNECTION_REFUSED
            await asyncio.sleep(0.05)

            snapshot = stats.snapshot()
            assert snapshot["active_flows"] == 0
            assert snapshot["total_flows"] == 1
            assert snapshot["total_closed_flows"] == 1
            assert snapshot["closed_flows"] == 1

            writer.close()
            await writer.wait_closed()
        finally:
            await _stop_server(server, task)


class TestConnectionDrop:
    async def test_drop_during_relay(self, echo_server):
        server, task = await _start_server()
        try:
            reader, writer = await _raw_connect(Address(server.host, server.port))
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            await reader.readexactly(2)

            from asyncio_socks_server.core.address import encode_address

            writer.write(
                b"\x05\x01\x00" + encode_address(echo_server.host, echo_server.port)
            )
            await writer.drain()
            await _read_reply(reader)

            # Abruptly close
            writer.close()
            await writer.wait_closed()
            await asyncio.sleep(0.1)
        finally:
            await _stop_server(server, task)

    async def test_multiple_rapid_connect_disconnect(self):
        server, task = await _start_server()
        try:
            for _ in range(10):
                reader, writer = await _raw_connect(Address(server.host, server.port))
                writer.write(b"\x05\x01\x00")
                await writer.drain()
                await reader.readexactly(2)
                writer.close()
                await writer.wait_closed()
            # Verify server is still responsive
            reader, writer = await _raw_connect(Address(server.host, server.port))
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            resp = await reader.readexactly(2)
            assert resp == b"\x05\x00"
            writer.close()
            await writer.wait_closed()
        finally:
            await _stop_server(server, task)


class TestErrorToRep:
    def test_connection_refused(self):
        assert Server._error_to_rep(ConnectionRefusedError()) == Rep.CONNECTION_REFUSED

    def test_network_unreachable(self):
        exc = OSError(101, "Network is unreachable")
        assert Server._error_to_rep(exc) == Rep.NETWORK_UNREACHABLE

    def test_generic_oserror(self):
        exc = OSError(99, "Some error")
        assert Server._error_to_rep(exc) == Rep.GENERAL_FAILURE

    def test_generic_exception(self):
        assert Server._error_to_rep(RuntimeError("oops")) == Rep.GENERAL_FAILURE
