"""Client edge cases: negotiation failures, unexpected responses."""

import asyncio
import socket

import pytest

from asyncio_socks_server.client.client import _happy_eyeballs_connect, connect
from asyncio_socks_server.core.types import Address


async def _fake_socks_server(*responses):
    """Start a fake SOCKS server that sends predefined responses.

    Returns (Address, close_event) where Address is the server's listen address.
    """
    close_event = asyncio.Event()
    received = []

    async def handler(reader, writer):
        try:
            while not close_event.is_set():
                try:
                    data = await asyncio.wait_for(reader.read(4096), timeout=0.5)
                    if not data:
                        break
                    received.append(data)
                except asyncio.TimeoutError:
                    continue
        finally:
            writer.close()
            await writer.wait_closed()

    srv = await asyncio.start_server(handler, "127.0.0.1", 0)
    addr = srv.sockets[0].getsockname()

    return Address(addr[0], addr[1]), srv, close_event, received


async def _fake_socks_server_with_responses(responses):
    """Start a fake SOCKS server that sends specific byte sequences.

    Each response is sent after receiving data from the client.
    Returns (Address, server, close_event).
    """
    close_event = asyncio.Event()
    resp_idx = [0]

    async def handler(reader, writer):
        try:
            while resp_idx[0] < len(responses):
                try:
                    data = await asyncio.wait_for(reader.read(4096), timeout=1.0)
                    if not data:
                        break
                    if resp_idx[0] < len(responses):
                        writer.write(responses[resp_idx[0]])
                        await writer.drain()
                        resp_idx[0] += 1
                except asyncio.TimeoutError:
                    break
        finally:
            writer.close()
            await writer.wait_closed()

    srv = await asyncio.start_server(handler, "127.0.0.1", 0)
    addr = srv.sockets[0].getsockname()
    return Address(addr[0], addr[1]), srv, close_event


class TestClientNegotiationFailures:
    async def test_proxy_returns_wrong_version(self):
        # Reply with version 0x04 instead of 0x05
        proxy_addr, srv, close = await _fake_socks_server_with_responses([b"\x04\x00"])
        try:
            with pytest.raises(Exception):
                await connect(proxy_addr, Address("127.0.0.1", 80))
        finally:
            close.set()
            srv.close()
            await srv.wait_closed()

    async def test_proxy_returns_no_acceptable_method(self):
        # Reply with 0xFF method (NO_ACCEPTABLE)
        proxy_addr, srv, close = await _fake_socks_server_with_responses([b"\x05\xff"])
        try:
            with pytest.raises(Exception, match="no acceptable"):
                await connect(proxy_addr, Address("127.0.0.1", 80))
        finally:
            close.set()
            srv.close()
            await srv.wait_closed()

    async def test_connect_reply_failure(self):
        # Method selection: accept NO_AUTH, then reply CONNECTION_REFUSED
        proxy_addr, srv, close = await _fake_socks_server_with_responses(
            [
                b"\x05\x00",  # Method reply: NO_AUTH
                # CONNECT reply: CONNECTION_REFUSED
                b"\x05\x05\x00\x01\x7f\x00\x00\x01\x00\x50",
            ]
        )
        try:
            with pytest.raises(Exception, match="refused|failed|CONNECT"):
                await connect(proxy_addr, Address("127.0.0.1", 80))
        finally:
            close.set()
            srv.close()
            await srv.wait_closed()

    async def test_connect_reply_wrong_version(self):
        proxy_addr, srv, close = await _fake_socks_server_with_responses(
            [
                b"\x05\x00",  # Method reply OK
                b"\x04\x00\x00\x01\x7f\x00\x00\x01\x00\x50",  # Wrong version in reply
            ]
        )
        try:
            with pytest.raises(Exception):
                await connect(proxy_addr, Address("127.0.0.1", 80))
        finally:
            close.set()
            srv.close()
            await srv.wait_closed()


class TestClientConnectionFailures:
    async def test_happy_eyeballs_falls_back_after_fast_first_failure(
        self, monkeypatch
    ):
        loop = asyncio.get_running_loop()
        attempts = []

        async def fake_getaddrinfo(host, port, type):
            return [
                (
                    socket.AF_INET6,
                    socket.SOCK_STREAM,
                    0,
                    "",
                    ("2001:db8::1", port, 0, 0),
                ),
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    0,
                    "",
                    ("127.0.0.1", port),
                ),
            ]

        async def fake_open_connection(host, port):
            attempts.append(host)
            if host == "2001:db8::1":
                raise OSError("ipv6 unavailable")
            return "reader", "writer"

        monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)
        monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)

        result = await _happy_eyeballs_connect(Address("example.test", 1080))

        assert result == ("reader", "writer")
        assert attempts == ["2001:db8::1", "127.0.0.1"]

    async def test_connection_refused(self):
        # Connect to a port that nobody is listening on
        proxy_addr = Address("127.0.0.1", 1)
        with pytest.raises((ConnectionError, OSError)):
            await connect(proxy_addr, Address("127.0.0.1", 80))

    async def test_auth_failure(self):
        # Test auth failure via real server
        from tests.conftest import _start_server, _stop_server

        server, task = await _start_server(auth=("user", "pass"))
        try:
            with pytest.raises(Exception, match="authentication failed"):
                await connect(
                    Address(server.host, server.port),
                    Address("127.0.0.1", 80),
                    username="user",
                    password="wrong",
                )
        finally:
            await _stop_server(server, task)
