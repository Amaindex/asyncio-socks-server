import asyncio

import pytest

from asyncio_socks_server import Addon, ChainRouter, IPFilter, TrafficCounter, connect
from asyncio_socks_server.core.protocol import build_udp_header, parse_udp_header
from asyncio_socks_server.core.types import Address, Direction
from tests.conftest import _start_server, _stop_server
from tests.e2e_helpers import open_udp_associate, read_socks_reply, socks5_connect


class TestBidirectionalData:
    async def test_simultaneous_bidirectional(self, echo_server):
        server, task = await _start_server()
        try:
            reader, writer = await socks5_connect(
                Address(server.host, server.port), echo_server
            )
            reply = await read_socks_reply(reader)
            assert reply[1] == 0x00

            writer.write(b"simul")
            await writer.drain()
            assert await asyncio.wait_for(reader.read(4096), timeout=2.0) == b"simul"

            writer.write(b"simul2")
            await writer.drain()
            assert await asyncio.wait_for(reader.read(4096), timeout=2.0) == b"simul2"

            writer.close()
            await writer.wait_closed()
        finally:
            await _stop_server(server, task)


class TestLargeDataChain:
    async def test_512kb_through_chain(self, echo_server):
        exit_server, exit_task = await _start_server()
        chain = ChainRouter(next_hop=f"127.0.0.1:{exit_server.port}")
        entry_server, entry_task = await _start_server(addons=[chain])

        try:
            conn = await connect(
                Address(entry_server.host, entry_server.port), echo_server
            )
            payload = b"X" * (512 * 1024)
            conn.writer.write(payload)
            await conn.writer.drain()

            received = b""
            while len(received) < len(payload):
                chunk = await asyncio.wait_for(conn.reader.read(65536), timeout=5.0)
                if not chunk:
                    break
                received += chunk

            assert received == payload
            conn.writer.close()
            await conn.writer.wait_closed()
        finally:
            await _stop_server(entry_server, entry_task)
            await _stop_server(exit_server, exit_task)


class TestMultiAddonComposition:
    async def test_ipfilter_and_traffic_counter(self, echo_server):
        counter = TrafficCounter()
        filter_addon = IPFilter(allowed=["127.0.0.0/8"])
        server, task = await _start_server(addons=[filter_addon, counter])

        try:
            conn = await connect(Address(server.host, server.port), echo_server)
            conn.writer.write(b"filtered")
            await conn.writer.drain()
            assert await conn.reader.read(4096) == b"filtered"
            conn.writer.close()
            await conn.writer.wait_closed()

            await asyncio.sleep(0.2)
            assert counter.connections == 1
            assert counter.bytes_up == 8
            assert counter.bytes_down == 8
        finally:
            await _stop_server(server, task)

    async def test_ipfilter_blocks_then_traffic_zero(self, echo_server):
        counter = TrafficCounter()
        filter_addon = IPFilter(blocked=["127.0.0.0/8"])
        server, task = await _start_server(addons=[filter_addon, counter])

        try:
            reader, writer = await socks5_connect(
                Address(server.host, server.port), echo_server
            )
            reply = await read_socks_reply(reader)
            assert reply[1] == 0x02
            writer.close()
            await writer.wait_closed()

            await asyncio.sleep(0.1)
            assert counter.connections == 0
        finally:
            await _stop_server(server, task)

    async def test_pipeline_and_chain_combined(self, echo_server):
        class UpperAddon(Addon):
            async def on_data(self, direction, data, flow):
                return data.upper()

        exit_server, exit_task = await _start_server(addons=[UpperAddon()])
        chain = ChainRouter(next_hop=f"127.0.0.1:{exit_server.port}")
        entry_server, entry_task = await _start_server(addons=[chain])

        try:
            conn = await connect(
                Address(entry_server.host, entry_server.port), echo_server
            )
            conn.writer.write(b"transform-me")
            await conn.writer.drain()
            assert await conn.reader.read(4096) == b"TRANSFORM-ME"
            conn.writer.close()
            await conn.writer.wait_closed()
        finally:
            await _stop_server(entry_server, entry_task)
            await _stop_server(exit_server, exit_task)


class TestAddonDataDrop:
    async def test_drop_addon_silences_upstream(self, echo_server):
        class DropUpstream(Addon):
            async def on_data(self, direction, data, flow):
                if direction == Direction.UPSTREAM:
                    return None
                return data

        server, task = await _start_server(addons=[DropUpstream()])
        try:
            reader, writer = await socks5_connect(
                Address(server.host, server.port), echo_server
            )
            reply = await read_socks_reply(reader)
            assert reply[1] == 0x00

            writer.write(b"dropped")
            await writer.drain()
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(reader.read(4096), timeout=0.5)

            writer.close()
            await writer.wait_closed()
        finally:
            await _stop_server(server, task)


class TestFlowBytesAccuracy:
    async def test_traffic_counter_through_chain(self, echo_server):
        exit_counter = TrafficCounter()
        exit_server, exit_task = await _start_server(addons=[exit_counter])

        entry_counter = TrafficCounter()
        chain = ChainRouter(next_hop=f"127.0.0.1:{exit_server.port}")
        entry_server, entry_task = await _start_server(addons=[entry_counter, chain])

        try:
            conn = await connect(
                Address(entry_server.host, entry_server.port), echo_server
            )
            conn.writer.write(b"12345")
            await conn.writer.drain()
            assert await conn.reader.read(4096) == b"12345"

            conn.writer.close()
            await conn.writer.wait_closed()
            await asyncio.sleep(0.3)

            assert entry_counter.connections == 1
            assert entry_counter.bytes_up == 5
            assert entry_counter.bytes_down == 5
            assert exit_counter.connections == 1
            assert exit_counter.bytes_up == 5
            assert exit_counter.bytes_down == 5
        finally:
            await _stop_server(entry_server, entry_task)
            await _stop_server(exit_server, exit_task)


class TestMixedProtocol:
    async def test_tcp_and_udp_concurrent(self, echo_server, udp_echo_server):
        server, task = await _start_server()
        try:
            tcp_reader, tcp_writer = await socks5_connect(
                Address(server.host, server.port), echo_server
            )
            reply = await read_socks_reply(tcp_reader)
            assert reply[1] == 0x00

            _, udp_writer, udp_bind = await open_udp_associate(
                Address(server.host, server.port)
            )

            tcp_writer.write(b"tcp-data")
            await tcp_writer.drain()

            echo_addr, _ = udp_echo_server
            loop = asyncio.get_running_loop()
            udp_received = loop.create_future()

            class ClientProto(asyncio.DatagramProtocol):
                def datagram_received(self, data, addr):
                    if not udp_received.done():
                        udp_received.set_result(data)

            transport, _ = await loop.create_datagram_endpoint(
                ClientProto,
                local_addr=("127.0.0.1", 0),
            )
            try:
                transport.sendto(
                    build_udp_header(echo_addr) + b"udp-data",
                    (udp_bind.host, udp_bind.port),
                )

                tcp_data = await asyncio.wait_for(tcp_reader.read(4096), timeout=2.0)
                assert tcp_data == b"tcp-data"

                udp_data = await asyncio.wait_for(udp_received, timeout=2.0)
                _, _, payload = parse_udp_header(udp_data)
                assert payload == b"udp-data"
            finally:
                transport.close()
                tcp_writer.close()
                await tcp_writer.wait_closed()
                udp_writer.close()
                await udp_writer.wait_closed()
        finally:
            await _stop_server(server, task)


class TestBinaryDataRoundtrip:
    async def test_null_bytes_and_binary(self, echo_server):
        server, task = await _start_server()
        try:
            conn = await connect(Address(server.host, server.port), echo_server)
            payload = b"\x00\x01\x02\xff\xfe\xfd" + bytes(range(256))
            conn.writer.write(payload)
            await conn.writer.drain()

            received = b""
            while len(received) < len(payload):
                chunk = await asyncio.wait_for(conn.reader.read(4096), timeout=3.0)
                if not chunk:
                    break
                received += chunk

            assert received == payload
            conn.writer.close()
            await conn.writer.wait_closed()
        finally:
            await _stop_server(server, task)

    async def test_binary_through_chain(self, echo_server):
        exit_server, exit_task = await _start_server()
        chain = ChainRouter(next_hop=f"127.0.0.1:{exit_server.port}")
        entry_server, entry_task = await _start_server(addons=[chain])

        try:
            conn = await connect(
                Address(entry_server.host, entry_server.port), echo_server
            )
            payload = bytes(range(256)) * 4
            conn.writer.write(payload)
            await conn.writer.drain()

            received = b""
            while len(received) < len(payload):
                chunk = await asyncio.wait_for(conn.reader.read(4096), timeout=3.0)
                if not chunk:
                    break
                received += chunk

            assert received == payload
            conn.writer.close()
            await conn.writer.wait_closed()
        finally:
            await _stop_server(entry_server, entry_task)
            await _stop_server(exit_server, exit_task)
