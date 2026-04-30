"""Tests for IPv6 dual-stack support."""

import asyncio
import ipaddress
import socket
import struct

import pytest

from asyncio_socks_server.core.address import encode_address
from asyncio_socks_server.core.protocol import build_udp_header
from asyncio_socks_server.core.types import Address
from asyncio_socks_server.server.server import Server


async def _start_server_ipv6(**kwargs):
    server = Server(host="::", port=0, **kwargs)
    task = asyncio.create_task(server._run())
    for _ in range(50):
        if server.port != 0:
            break
        await asyncio.sleep(0.01)
    return server, task


async def _stop_server(server, task):
    server.request_shutdown()
    await task


async def _skip_bind_address(reader):
    atyp = (await reader.readexactly(1))[0]
    if atyp == 0x01:
        await reader.readexactly(4 + 2)
    elif atyp == 0x04:
        await reader.readexactly(16 + 2)
    elif atyp == 0x03:
        length = (await reader.readexactly(1))[0]
        await reader.readexactly(length + 2)


async def _socks5_connect_ipv6(proxy_addr: Address, target: Address):
    reader, writer = await asyncio.open_connection(proxy_addr.host, proxy_addr.port)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    resp = await reader.readexactly(2)
    assert resp[0] == 0x05 and resp[1] == 0x00
    writer.write(b"\x05\x01\x00" + encode_address(target.host, target.port))
    await writer.drain()
    reply = await reader.readexactly(3)
    assert reply[1] == 0x00
    await _skip_bind_address(reader)
    return reader, writer


class TestIPv6TCP:
    @pytest.fixture
    async def ipv6_echo_server(self):
        async def handler(reader, writer):
            try:
                while True:
                    data = await reader.read(4096)
                    if not data:
                        break
                    writer.write(data)
                    await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        srv = await asyncio.start_server(handler, "::1", 0)
        addr = srv.sockets[0].getsockname()
        yield Address(addr[0], addr[1])
        srv.close()
        await srv.wait_closed()

    async def test_tcp_connect_ipv6_loopback(self, ipv6_echo_server):
        server, task = await _start_server_ipv6()
        try:
            tcp_r, tcp_w = await _socks5_connect_ipv6(
                Address("::1", server.port), ipv6_echo_server
            )
            tcp_w.write(b"hello ipv6")
            await tcp_w.drain()
            data = await tcp_r.read(1024)
            assert data == b"hello ipv6"
            tcp_w.close()
            await tcp_w.wait_closed()
        finally:
            await _stop_server(server, task)

    async def test_tcp_ipv4_on_dualstack(self):
        async def echo_handler(reader, writer):
            try:
                while True:
                    data = await reader.read(4096)
                    if not data:
                        break
                    writer.write(data)
                    await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        echo_srv = await asyncio.start_server(echo_handler, "127.0.0.1", 0)
        echo_addr = echo_srv.sockets[0].getsockname()
        echo_target = Address(echo_addr[0], echo_addr[1])

        server, task = await _start_server_ipv6()
        try:
            r, w = await asyncio.open_connection("127.0.0.1", server.port)
            w.write(b"\x05\x01\x00")
            await w.drain()
            resp = await r.readexactly(2)
            assert resp[1] == 0x00
            target_bytes = encode_address(echo_target.host, echo_target.port)
            w.write(b"\x05\x01\x00" + target_bytes)
            await w.drain()
            reply = await r.readexactly(3)
            assert reply[1] == 0x00
            await _skip_bind_address(r)

            w.write(b"dualstack works")
            await w.drain()
            data = await r.read(1024)
            assert data == b"dualstack works"
            w.close()
            await w.wait_closed()
        finally:
            await _stop_server(server, task)
            echo_srv.close()
            await echo_srv.wait_closed()


class TestIPv6UDP:
    @pytest.fixture
    async def ipv6_udp_echo_server(self):
        received = []

        class Protocol(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, addr):
                received.append((data, addr))
                self.transport.sendto(data, addr)

        loop = asyncio.get_running_loop()
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.bind(("::1", 0))
        s.setblocking(False)
        transport, _ = await loop.create_datagram_endpoint(Protocol, sock=s)
        sockname = s.getsockname()
        yield Address(sockname[0], sockname[1]), received
        transport.close()

    async def test_udp_associate_ipv6(self, ipv6_udp_echo_server):
        echo_addr, _ = ipv6_udp_echo_server
        server, task = await _start_server_ipv6()
        try:
            # SOCKS5 handshake via IPv6
            reader, writer = await asyncio.open_connection("::1", server.port)
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            resp = await reader.readexactly(2)
            assert resp[0] == 0x05 and resp[1] == 0x00

            # UDP ASSOCIATE
            writer.write(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()

            reply = await reader.readexactly(3)
            assert reply[0] == 0x05
            assert reply[1] == 0x00

            atyp = (await reader.readexactly(1))[0]
            if atyp == 0x04:
                host_bytes = await reader.readexactly(16)
                host = str(ipaddress.IPv6Address(host_bytes))
            elif atyp == 0x01:
                host_bytes = await reader.readexactly(4)
                host = ipaddress.IPv4Address(host_bytes).compressed
            else:
                length = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(length)).decode("ascii")

            port_bytes = await reader.readexactly(2)
            port = struct.unpack("!H", port_bytes)[0]

            udp_bind = Address(host, port)

            # Client UDP socket on IPv6
            loop = asyncio.get_running_loop()
            received = loop.create_future()

            class ClientProtocol(asyncio.DatagramProtocol):
                def datagram_received(self, data, addr):
                    if not received.done():
                        received.set_result(data)

            client_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            client_sock.bind(("::1", 0))
            client_sock.setblocking(False)
            transport, _ = await loop.create_datagram_endpoint(
                ClientProtocol, sock=client_sock
            )

            datagram = build_udp_header(echo_addr) + b"hello ipv6 udp"
            transport.sendto(datagram, (udp_bind.host, udp_bind.port))

            try:
                resp_data = await asyncio.wait_for(received, timeout=2.0)
                from asyncio_socks_server.core.protocol import parse_udp_header

                _, _, payload = parse_udp_header(resp_data)
                assert payload == b"hello ipv6 udp"
            finally:
                transport.close()
                writer.close()
                await writer.wait_closed()
        finally:
            await _stop_server(server, task)
