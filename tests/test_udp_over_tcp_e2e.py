"""End-to-end test: UDP client → Entry SOCKS5 server → Exit server → UDP echo."""

import asyncio
import socket
import struct

from asyncio_socks_server.addons.udp_over_tcp_entry import UdpOverTcpEntry
from asyncio_socks_server.core.protocol import build_udp_header, parse_udp_header
from asyncio_socks_server.core.types import Address
from asyncio_socks_server.server.server import Server
from asyncio_socks_server.server.udp_over_tcp_exit import UdpOverTcpExitServer


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


async def _start_exit_server(**kwargs):
    server = UdpOverTcpExitServer(host="127.0.0.1", port=0, **kwargs)
    task = asyncio.create_task(server._run())
    for _ in range(50):
        if server.port != 0:
            break
        await asyncio.sleep(0.01)
    return server, task


async def _stop_exit_server(server, task):
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


class TestUdpOverTcpE2E:
    async def test_full_chain_udp_roundtrip(self):
        """UDP client → Entry SOCKS5 → Exit server → UDP echo → back."""

        # 1. UDP echo server
        class EchoProtocol(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, addr):
                self.transport.sendto(data, addr)

        loop = asyncio.get_running_loop()
        echo_transport, _ = await loop.create_datagram_endpoint(
            EchoProtocol, local_addr=("127.0.0.1", 0)
        )
        echo_sock = echo_transport.get_extra_info("socket")
        echo_sockname = echo_sock.getsockname() if echo_sock else ("127.0.0.1", 0)
        echo_addr = Address(echo_sockname[0], echo_sockname[1])

        # 2. Exit server
        exit_srv, exit_task = await _start_exit_server()

        # 3. Entry SOCKS5 server with UdpOverTcpEntry addon
        entry_addon = UdpOverTcpEntry(f"127.0.0.1:{exit_srv.port}")
        entry_srv, entry_task = await _start_server(addons=[entry_addon])

        try:
            # 4. Client: SOCKS5 handshake
            reader, writer = await asyncio.open_connection("127.0.0.1", entry_srv.port)
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            resp = await reader.readexactly(2)
            assert resp == b"\x05\x00"

            # 5. UDP ASSOCIATE
            writer.write(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()

            reply = await reader.readexactly(3)
            assert reply[0] == 0x05
            assert reply[1] == 0x00

            # Read bind address
            atyp = (await reader.readexactly(1))[0]
            if atyp == 0x01:
                host_bytes = await reader.readexactly(4)
                import ipaddress

                host = ipaddress.IPv4Address(host_bytes).compressed
            elif atyp == 0x04:
                host_bytes = await reader.readexactly(16)
                host = str(ipaddress.IPv6Address(host_bytes))
            else:
                length = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(length)).decode("ascii")
            port_bytes = await reader.readexactly(2)
            port = struct.unpack("!H", port_bytes)[0]
            udp_bind = Address(host, port)

            # 6. Client sends UDP datagram through the entry server's UDP bind
            received_future = loop.create_future()

            class ClientProtocol(asyncio.DatagramProtocol):
                def datagram_received(self, data, addr):
                    if not received_future.done():
                        received_future.set_result(data)

            client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_sock.bind(("127.0.0.1", 0))
            client_sock.setblocking(False)
            client_transport, _ = await loop.create_datagram_endpoint(
                ClientProtocol, sock=client_sock
            )

            datagram = build_udp_header(echo_addr) + b"hello chain"
            client_transport.sendto(datagram, (udp_bind.host, udp_bind.port))

            resp_data = await asyncio.wait_for(received_future, timeout=3.0)
            _, _, payload = parse_udp_header(resp_data)
            assert payload == b"hello chain"

            client_transport.close()
            writer.close()
            await writer.wait_closed()
        finally:
            await _stop_server(entry_srv, entry_task)
            await _stop_exit_server(exit_srv, exit_task)
            echo_transport.close()

    async def test_chain_multiple_datagrams(self):
        """Multiple UDP datagrams through the full chain."""

        class EchoProtocol(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, addr):
                self.transport.sendto(data, addr)

        loop = asyncio.get_running_loop()
        echo_transport, _ = await loop.create_datagram_endpoint(
            EchoProtocol, local_addr=("127.0.0.1", 0)
        )
        echo_sock = echo_transport.get_extra_info("socket")
        echo_sockname = echo_sock.getsockname() if echo_sock else ("127.0.0.1", 0)
        echo_addr = Address(echo_sockname[0], echo_sockname[1])

        exit_srv, exit_task = await _start_exit_server()
        entry_addon = UdpOverTcpEntry(f"127.0.0.1:{exit_srv.port}")
        entry_srv, entry_task = await _start_server(addons=[entry_addon])

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", entry_srv.port)
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            resp = await reader.readexactly(2)
            assert resp == b"\x05\x00"

            writer.write(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            reply = await reader.readexactly(3)
            assert reply[1] == 0x00

            atyp = (await reader.readexactly(1))[0]
            if atyp == 0x01:
                host_bytes = await reader.readexactly(4)
                import ipaddress

                host = ipaddress.IPv4Address(host_bytes).compressed
            elif atyp == 0x04:
                host_bytes = await reader.readexactly(16)
                host = str(ipaddress.IPv6Address(host_bytes))
            else:
                length = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(length)).decode("ascii")
            port_bytes = await reader.readexactly(2)
            port = struct.unpack("!H", port_bytes)[0]
            udp_bind = Address(host, port)

            received_queue: asyncio.Queue[bytes] = asyncio.Queue()

            class ClientProtocol(asyncio.DatagramProtocol):
                def datagram_received(self, data, addr):
                    received_queue.put_nowait(data)

            client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_sock.bind(("127.0.0.1", 0))
            client_sock.setblocking(False)
            client_transport, _ = await loop.create_datagram_endpoint(
                ClientProtocol, sock=client_sock
            )

            for i in range(3):
                datagram = build_udp_header(echo_addr) + f"pkt{i}".encode()
                client_transport.sendto(datagram, (udp_bind.host, udp_bind.port))
                await asyncio.sleep(0.05)

            for i in range(3):
                resp_data = await asyncio.wait_for(received_queue.get(), timeout=3.0)
                _, _, payload = parse_udp_header(resp_data)
                assert payload == f"pkt{i}".encode()

            client_transport.close()
            writer.close()
            await writer.wait_closed()
        finally:
            await _stop_server(entry_srv, entry_task)
            await _stop_exit_server(exit_srv, exit_task)
            echo_transport.close()
