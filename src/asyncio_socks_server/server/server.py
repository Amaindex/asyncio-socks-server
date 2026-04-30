from __future__ import annotations

import asyncio
import ipaddress
import itertools
import socket
import time

from asyncio_socks_server.addons.base import Addon
from asyncio_socks_server.addons.manager import AddonManager
from asyncio_socks_server.core.address import encode_reply
from asyncio_socks_server.core.logging import fmt_bytes, fmt_connection, get_logger
from asyncio_socks_server.core.protocol import (
    build_auth_reply,
    build_method_reply,
    parse_method_selection,
    parse_request,
    parse_username_password,
)
from asyncio_socks_server.core.socket import (
    create_dualstack_tcp_socket,
    create_dualstack_udp_socket,
)
from asyncio_socks_server.core.types import Address, AuthMethod, Cmd, Flow, Rep
from asyncio_socks_server.server.connection import Connection
from asyncio_socks_server.server.tcp_relay import handle_tcp_relay
from asyncio_socks_server.server.udp_relay import UdpRelay, UdpRelayBase


class Server:
    def __init__(
        self,
        host: str = "::",
        port: int = 1080,
        addons: list[Addon] | None = None,
        auth: tuple[str, str] | None = None,
        log_level: str = "INFO",
        shutdown_timeout: float | None = 30.0,
    ):
        self.host = host
        self.port = port
        self.auth = auth
        self.log_level = log_level
        self.shutdown_timeout = shutdown_timeout
        self._addon_manager = AddonManager(addons)
        self._shutdown_event = asyncio.Event()
        self._flow_seq = itertools.count(1)
        self._client_tasks: set[asyncio.Task] = set()

    def run(self) -> None:
        asyncio.run(self._run())

    def _install_signal_handlers(self) -> None:
        import signal

        loop = asyncio.get_running_loop()

        def _signal_handler():
            self.request_shutdown()

        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, _signal_handler)

    async def _run(self) -> None:
        from asyncio_socks_server.core.logging import setup_logging

        setup_logging(self.log_level)
        logger = get_logger()

        await self._addon_manager.dispatch_start()
        self._install_signal_handlers()

        sock = create_dualstack_tcp_socket(self.host, self.port)
        sock.setblocking(False)
        srv = await asyncio.start_server(
            self._handle_client,
            sock=sock,
        )
        addr = srv.sockets[0].getsockname()
        self.port = addr[1]
        logger.info(f"server started on {self.host}:{self.port}")

        try:
            await self._shutdown_event.wait()
        finally:
            srv.close()
            await srv.wait_closed()
            await self._wait_for_client_tasks()
            await self._addon_manager.dispatch_stop()
            logger.info("server stopped")

    async def _wait_for_client_tasks(self) -> None:
        if not self._client_tasks:
            return

        tasks = set(self._client_tasks)
        try:
            if self.shutdown_timeout is None:
                await asyncio.gather(*tasks, return_exceptions=True)
            else:
                await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=self.shutdown_timeout,
                )
        except TimeoutError:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._client_tasks.add(task)
        try:
            await self._do_handshake_and_relay(reader, writer)
        except Exception as e:
            await self._addon_manager.dispatch_error(e)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
            if task is not None:
                self._client_tasks.discard(task)

    async def _do_handshake_and_relay(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        header = await reader.readexactly(2)
        version, method_count = header[0], header[1]
        method_data = await reader.readexactly(method_count)
        _, methods = parse_method_selection(
            bytes([version, method_count]) + method_data
        )

        if self.auth:
            if AuthMethod.USERNAME_PASSWORD not in methods:
                writer.write(build_method_reply(AuthMethod.NO_ACCEPTABLE))
                await writer.drain()
                return
            writer.write(build_method_reply(AuthMethod.USERNAME_PASSWORD))
            await writer.drain()

            username, password = await parse_username_password(reader)

            auth_result = await self._addon_manager.dispatch_auth(username, password)
            if auth_result is not None:
                success = auth_result
            else:
                success = username == self.auth[0] and password == self.auth[1]

            writer.write(build_auth_reply(success))
            await writer.drain()
            if not success:
                return
        else:
            if AuthMethod.NO_AUTH not in methods:
                writer.write(build_method_reply(AuthMethod.NO_ACCEPTABLE))
                await writer.drain()
                return
            writer.write(build_method_reply(AuthMethod.NO_AUTH))
            await writer.drain()

        cmd, dst = await parse_request(reader)

        peername = writer.get_extra_info("peername")
        src = Address(peername[0], peername[1]) if peername else Address("::", 0)

        if cmd == Cmd.CONNECT:
            await self._handle_connect(reader, writer, src, dst)
        elif cmd == Cmd.UDP_ASSOCIATE:
            await self._handle_udp_associate(reader, writer, src, dst)
        else:
            writer.write(encode_reply(Rep.COMMAND_NOT_SUPPORTED))
            await writer.drain()

    async def _handle_connect(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        src: Address,
        dst: Address,
    ) -> None:
        logger = get_logger()
        flow = Flow(
            id=next(self._flow_seq),
            src=src,
            dst=dst,
            protocol="tcp",
            started_at=time.monotonic(),
        )
        conn: Connection | None = None

        try:
            addon_result = await self._addon_manager.dispatch_connect(flow)
        except Exception as e:
            logger.error(f"{fmt_connection(src, dst)} | addon error: {e}")
            client_writer.write(encode_reply(Rep.CONNECTION_NOT_ALLOWED))
            await client_writer.drain()
            return
        if addon_result is not None and isinstance(addon_result, Connection):
            conn = addon_result
        else:
            try:
                remote_reader, remote_writer = await asyncio.open_connection(
                    dst.host, dst.port
                )
                sock = remote_writer.get_extra_info("socket")
                sockname = sock.getsockname() if sock else ("::", 0)
                conn = Connection(
                    reader=remote_reader,
                    writer=remote_writer,
                    address=Address(sockname[0], sockname[1]),
                )
            except (ConnectionError, OSError) as e:
                logger.error(f"{fmt_connection(src, dst)} | {e}")
                rep = self._error_to_rep(e)
                client_writer.write(encode_reply(rep))
                await client_writer.drain()
                return

        client_writer.write(
            encode_reply(Rep.SUCCEEDED, conn.address.host, conn.address.port)
        )
        await client_writer.drain()

        logger.info(f"{fmt_connection(src, dst)} | connected")

        try:
            await handle_tcp_relay(
                client_reader,
                client_writer,
                conn.reader,
                conn.writer,
                self._addon_manager,
                flow,
            )
        finally:
            elapsed = time.monotonic() - flow.started_at
            logger.info(
                f"{fmt_connection(src, dst)} | "
                f"closed {elapsed:.1f}s "
                f"↑{fmt_bytes(flow.bytes_up)} ↓{fmt_bytes(flow.bytes_down)}"
            )
            await self._addon_manager.dispatch_flow_close(flow)

    async def _handle_udp_associate(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        src: Address,
        dst: Address,
    ) -> None:
        logger = get_logger()
        flow = Flow(
            id=next(self._flow_seq),
            src=src,
            dst=dst,
            protocol="udp",
            started_at=time.monotonic(),
        )

        try:
            relay: UdpRelayBase = (
                await self._addon_manager.dispatch_udp_associate(flow)
            ) or UdpRelay(client_addr=src, flow=flow)
        except Exception as e:
            logger.error(f"{fmt_connection(src, dst)} | addon error: {e}")
            writer.write(encode_reply(Rep.CONNECTION_NOT_ALLOWED))
            await writer.drain()
            return

        client_transport: asyncio.DatagramTransport | None = None
        reply_sent = False

        try:
            await relay.start()

            loop = asyncio.get_running_loop()
            client_udp_sock = _create_client_udp_socket(src.host)
            client_udp_sock.setblocking(False)
            client_transport, _ = await loop.create_datagram_endpoint(
                lambda: _ClientUdpProtocol(relay),
                sock=client_udp_sock,
            )
            client_sock = client_transport.get_extra_info("socket")
            fallback = ("::", 0)
            client_sockname = client_sock.getsockname() if client_sock else fallback
            client_bind = Address(client_sockname[0], client_sockname[1])

            relay.set_client_transport(client_transport)

            writer.write(
                encode_reply(Rep.SUCCEEDED, client_bind.host, client_bind.port)
            )
            await writer.drain()
            reply_sent = True

            logger.info(f"{fmt_connection(src, dst)} | udp associate started")

            await reader.read()
        except Exception as e:
            logger.error(f"{fmt_connection(src, dst)} | udp associate error: {e}")
            await self._addon_manager.dispatch_error(e)
            if not reply_sent:
                try:
                    writer.write(encode_reply(Rep.GENERAL_FAILURE))
                    await writer.drain()
                except (ConnectionError, OSError):
                    pass
        finally:
            await relay.stop()
            if client_transport and not client_transport.is_closing():
                client_transport.close()
            logger.info(
                f"{fmt_connection(src, dst)} | "
                f"udp closed ↑{fmt_bytes(flow.bytes_up)} ↓{fmt_bytes(flow.bytes_down)}"
            )
            await self._addon_manager.dispatch_flow_close(flow)

    @staticmethod
    def _error_to_rep(exc: Exception) -> Rep:
        if isinstance(exc, ConnectionRefusedError):
            return Rep.CONNECTION_REFUSED
        if isinstance(exc, OSError) and exc.errno == 101:
            return Rep.NETWORK_UNREACHABLE
        return Rep.GENERAL_FAILURE

    def request_shutdown(self) -> None:
        self._shutdown_event.set()


def _create_client_udp_socket(host: str) -> socket.socket:
    try:
        ipaddress.IPv6Address(host)
    except ValueError:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", 0))
        return sock
    return create_dualstack_udp_socket("::", 0)


class _ClientUdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, relay: UdpRelayBase) -> None:
        self._relay = relay

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        pass

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self._relay.handle_client_datagram(data, addr)

    def error_received(self, exc: Exception) -> None:
        pass
