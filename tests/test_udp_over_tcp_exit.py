"""Tests for UdpOverTcpExitServer."""

import asyncio

from asyncio_socks_server.core.types import Address
from asyncio_socks_server.server.udp_over_tcp import encode_udp_frame, read_udp_frame
from asyncio_socks_server.server.udp_over_tcp_exit import UdpOverTcpExitServer


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


class TestUdpOverTcpExit:
    async def test_tcp_to_udp_roundtrip(self):
        """Send UDP-over-TCP frame → exit server → UDP echo → TCP frame back."""
        # UDP echo server
        received = []

        class EchoProtocol(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, addr):
                received.append((data, addr))
                self.transport.sendto(data, addr)

        loop = asyncio.get_running_loop()
        echo_transport, _ = await loop.create_datagram_endpoint(
            EchoProtocol, local_addr=("127.0.0.1", 0)
        )
        echo_sock = echo_transport.get_extra_info("socket")
        echo_sockname = echo_sock.getsockname() if echo_sock else ("127.0.0.1", 0)
        echo_addr = Address(echo_sockname[0], echo_sockname[1])

        exit_srv, exit_task = await _start_exit_server()
        try:
            # Connect to exit server via TCP
            reader, writer = await asyncio.open_connection("127.0.0.1", exit_srv.port)

            # Send UDP-over-TCP frame targeting the echo server
            frame = await encode_udp_frame(echo_addr, b"hello exit")
            writer.write(frame)
            await writer.drain()

            # Wait for echo reply to come back via TCP
            src_addr, payload = await asyncio.wait_for(
                read_udp_frame(reader), timeout=2.0
            )
            assert payload == b"hello exit"
            assert src_addr.host == echo_addr.host
            assert src_addr.port == echo_addr.port

            writer.close()
            await writer.wait_closed()
        finally:
            await _stop_exit_server(exit_srv, exit_task)
            echo_transport.close()

    async def test_multiple_datagrams(self):
        """Multiple frames in sequence."""

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
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", exit_srv.port)

            for i in range(5):
                frame = await encode_udp_frame(echo_addr, f"msg{i}".encode())
                writer.write(frame)
            await writer.drain()

            for i in range(5):
                src_addr, payload = await asyncio.wait_for(
                    read_udp_frame(reader), timeout=2.0
                )
                assert payload == f"msg{i}".encode()

            writer.close()
            await writer.wait_closed()
        finally:
            await _stop_exit_server(exit_srv, exit_task)
            echo_transport.close()
