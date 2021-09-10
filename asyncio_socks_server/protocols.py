import asyncio
import socket
from asyncio.streams import StreamReader
from socket import AF_INET, AF_INET6, inet_ntop, inet_pton
from typing import Dict, Optional, Tuple

from asyncio_socks_server.authenticators import AUTHENTICATORS_CLS_LIST
from asyncio_socks_server.config import Config
from asyncio_socks_server.exceptions import (
    AuthenticationError,
    CommandExecError,
    HeaderParseError,
    NoAtypAllowed,
    NoAuthMethodAllowed,
    NoCommandAllowed,
    NoVersionAllowed,
    SocksException,
)
from asyncio_socks_server.logger import access_logger, error_logger, logger
from asyncio_socks_server.utils import get_atyp_from_host
from asyncio_socks_server.values import Atyp, Command, Status


class LocalTCP(asyncio.Protocol):
    STAGE_NEGOTIATE = 0
    STAGE_CONNECT = 1
    STAGE_UDP_ASSOCIATE = 3
    STAGE_DESTROY = -1

    def __init__(self, config: Config):
        self.config = config
        self.stage = None
        self.transport = None
        self.remote_tcp = None
        self.local_udp = None
        self.peername = None
        self.stream_reader = StreamReader()
        self.is_closing = False
        self.__init_authenticator_cls()
        self.__init_validator()

    def __init_authenticator_cls(self):
        for cls in AUTHENTICATORS_CLS_LIST:
            if cls.METHOD == self.config.AUTH_METHOD:
                self.authenticator_cls = cls

    def __init_validator(self):
        pass

    def write(self, data):
        if not self.transport.is_closing():
            self.transport.write(data)

    def connection_made(self, transport):
        self.transport = transport
        self.peername = transport.get_extra_info("peername")
        self.stream_reader.set_transport(transport)
        loop = asyncio.get_running_loop()
        loop.create_task(self.negotiate_task())
        self.stage = self.STAGE_NEGOTIATE

        self.config.ACCESS_LOG and access_logger.debug(
            f"Local TCP connection made {self.peername}"
        )

    async def negotiate_task(self):
        def gen_reply(
            status: Status,
            bind_host: str = self.config.BIND_HOST,
            bind_port: int = 0,
        ) -> bytes:
            """
            Constructing a response for socks5.
            """
            VER, RSV = b"\x05", b"\x00"
            ATYP = get_atyp_from_host(bind_host)
            if ATYP == Atyp.IPV4:
                BND_ADDR = inet_pton(AF_INET, bind_host)
            elif ATYP == Atyp.IPV6:
                BND_ADDR = inet_pton(AF_INET6, bind_host)
            else:
                BND_ADDR = len(bind_host).to_bytes(2, "big") + bind_host.encode("UTF-8")
            REP = status.to_bytes(1, "big")
            ATYP = ATYP.to_bytes(1, "big")
            BND_PORT = int(bind_port).to_bytes(2, "big")
            return VER + REP + RSV + ATYP + BND_ADDR + BND_PORT

        try:
            VER, NMETHODS = await self.stream_reader.readexactly(2)
            if VER != 5:
                self.transport.write(b"\x05\xff")
                raise NoVersionAllowed(f"Unsupported socks version {VER}!")
            METHODS = set(await self.stream_reader.readexactly(NMETHODS))
            authenticator = self.authenticator_cls(
                self.stream_reader, self.transport, self.config
            )
            METHOD = authenticator.select_method(METHODS)
            self.transport.write(b"\x05" + METHOD.to_bytes(1, "big"))
            if METHOD == 0xFF:
                raise NoAuthMethodAllowed("No authentication methods available")
            await authenticator.authenticate()

            VER, CMD, RSV, ATYP = await self.stream_reader.readexactly(4)
            if ATYP == Atyp.IPV4:
                DST_ADDR = inet_ntop(AF_INET, await self.stream_reader.readexactly(4))
            elif ATYP == Atyp.DOMAIN:
                domain_len = int.from_bytes(
                    await self.stream_reader.readexactly(1), "big"
                )
                DST_ADDR = (await self.stream_reader.readexactly(domain_len)).decode()
            elif ATYP == Atyp.IPV6:
                DST_ADDR = inet_ntop(AF_INET6, await self.stream_reader.readexactly(16))
            else:
                self.transport.write(gen_reply(Status.ADDRESS_TYPE_NOT_SUPPORTED))
                raise NoAtypAllowed(f"Unsupported ATYP value: {ATYP}")
            DST_PORT = int.from_bytes(await self.stream_reader.readexactly(2), "big")

            if CMD == Command.CONNECT:
                try:
                    loop = asyncio.get_running_loop()
                    task = loop.create_connection(
                        lambda: RemoteTCP(self, self.config), DST_ADDR, DST_PORT
                    )
                    _, remote_tcp = await asyncio.wait_for(task, 5)
                except ConnectionRefusedError:
                    self.transport.write(gen_reply(Status.CONNECTION_REFUSED))
                    raise CommandExecError("CONNECTION_REFUSED") from None
                except socket.gaierror:
                    self.transport.write(gen_reply(Status.HOST_UNREACHABLE))
                    raise CommandExecError("HOST_UNREACHABLE") from None
                except Exception:
                    self.transport.write(gen_reply(Status.GENERAL_SOCKS_SERVER_FAILURE))
                    raise CommandExecError("GENERAL_SOCKS_SERVER_FAILURE") from None
                else:
                    self.remote_tcp = remote_tcp
                    BIND_ADDR, BIND_PORT = self.transport.get_extra_info("sockname")
                    self.transport.write(
                        gen_reply(Status.SUCCEEDED, BIND_ADDR, BIND_PORT)
                    )
                    self.stage = self.STAGE_CONNECT

                    self.config.ACCESS_LOG and access_logger.info(
                        f"TCP streaming between {self.peername} and {self.remote_tcp.peername}"
                    )
            elif CMD == Command.UDP_ASSOCIATE:
                try:
                    loop = asyncio.get_running_loop()
                    task = loop.create_datagram_endpoint(
                        lambda: LocalUDP((DST_ADDR, DST_PORT), self.config),
                        local_addr=("0.0.0.0", 0),
                    )
                    udp_transport, local_udp = await asyncio.wait_for(task, 5)
                except Exception:
                    self.transport.write(gen_reply(Status.GENERAL_SOCKS_SERVER_FAILURE))
                    raise CommandExecError("GENERAL_SOCKS_SERVER_FAILURE") from None
                else:
                    self.local_udp = local_udp
                    BIND_ADDR = self.config.BIND_HOST
                    _, BIND_PORT = udp_transport.get_extra_info("sockname")
                    self.transport.write(
                        gen_reply(Status.SUCCEEDED, BIND_ADDR, BIND_PORT)
                    )
                    self.stage = self.STAGE_UDP_ASSOCIATE

                    self.config.ACCESS_LOG and access_logger.info(
                        f"UDP relay opened by {self.peername} at port {BIND_PORT}"
                    )
            else:
                self.transport.write(gen_reply(Status.COMMAND_NOT_SUPPORTED))
                raise NoCommandAllowed(f"Unsupported CMD value: {CMD}")

        except (SocksException, ConnectionError, ValueError) as e:
            error_logger.warning(f"{e} during the negotiation with {self.peername}")
            self.close()

    def data_received(self, data):
        if self.stage == self.STAGE_NEGOTIATE:
            self.stream_reader.feed_data(data)
        elif self.stage == self.STAGE_CONNECT:
            self.remote_tcp.write(data)
        elif self.stage == self.STAGE_UDP_ASSOCIATE:
            pass
        elif self.stage == self.STAGE_DESTROY:
            self.close()

    def eof_received(self):
        self.close()

    def connection_lost(self, exc: Optional[Exception]) -> None:
        self.close()

    def close(self):
        if self.is_closing:
            return

        self.stage = self.STAGE_DESTROY
        self.is_closing = True
        self.transport and self.transport.close()
        self.remote_tcp and self.remote_tcp.close()
        self.local_udp and self.local_udp.close()

        self.config.ACCESS_LOG and access_logger.debug(
            f"Local TCP connection closed {self.peername}"
        )


class RemoteTCP(asyncio.Protocol):
    def __init__(self, local_tcp, config: Config):
        self.local_tcp = local_tcp
        self.config = config
        self.peername = None
        self.transport = None
        self.is_closing = False

    def write(self, data):
        if not self.transport.is_closing():
            self.transport.write(data)

    def connection_made(self, transport):
        self.transport = transport
        self.peername = transport.get_extra_info("peername")

        self.config.ACCESS_LOG and access_logger.debug(
            f"Remote TCP connection made {self.peername}"
        )

    def data_received(self, data):
        self.local_tcp.write(data)

    def eof_received(self):
        self.close()

    def connection_lost(self, exc):
        self.close()

    def close(self):
        if self.is_closing:
            return
        self.is_closing = True
        self.transport and self.transport.close()
        self.local_tcp.close()

        self.config.ACCESS_LOG and access_logger.debug(
            f"Remote TCP connection closed {self.peername}"
        )


class LocalUDP(asyncio.DatagramProtocol):
    def __init__(self, host_port_limit: Tuple[str, int], config: Config):
        self.host_port_limit = host_port_limit
        self.config = config
        self.transport = None
        self.sockname = None
        self.remote_udp_table = {}
        self.is_closing = False

    def write(self, data, port_addr):
        if not self.transport.is_closing():
            self.transport.sendto(data, port_addr)

    def connection_made(self, transport) -> None:
        self.transport = transport
        self.sockname = transport.get_extra_info("sockname")

        self.config.ACCESS_LOG and access_logger.debug(
            f"Local UDP endpoint made {self.sockname}"
        )

    @staticmethod
    def parse_udp_request_header(data: bytes):
        length = 0
        RSV = data[length : length + 2]
        length += 2
        FRAG = data[length : length + 1]
        if int.from_bytes(FRAG, "big") != 0:
            raise HeaderParseError()
        length += 1
        ATYP = int.from_bytes(data[length : length + 1], "big")
        length += 1
        if ATYP == Atyp.IPV4:
            ipv4 = data[length : length + 4]
            DST_ADDR = inet_ntop(AF_INET, ipv4)
            length += 4
        elif ATYP == Atyp.DOMAIN:
            addr_len = int.from_bytes(data[length : length + 1], byteorder="big")
            length += 1
            DST_ADDR = data[length : length + addr_len].decode()
            length += addr_len
        elif ATYP == Atyp.IPV6:
            ipv6 = data[length : length + 16]
            DST_ADDR = inet_ntop(AF_INET6, ipv6)
            length += 16
        else:
            raise HeaderParseError()
        DST_PORT = int.from_bytes(data[length : length + 2], "big")
        length += 2
        if length > len(data):
            raise HeaderParseError()
        return RSV, FRAG, ATYP, DST_ADDR, DST_PORT, length

    def datagram_received(self, data: bytes, local_host_port: Tuple[str, int]):
        cond1 = self.host_port_limit in (("0.0.0.0", 0), ("::", 0))
        cond2 = self.host_port_limit == local_host_port
        cond3 = self.config.UDP_ORIGIN_LIMIT == False
        if not (cond1 or cond2 or cond3):
            return
        loop = asyncio.get_event_loop()
        loop.create_task(self.relay_task(data, local_host_port))

    async def relay_task(self, data: bytes, local_host_port: Tuple[str, int]):
        try:
            (
                RSV,
                FRAG,
                ATYP,
                DST_ADDR,
                DST_PORT,
                header_length,
            ) = self.parse_udp_request_header(data)

            if local_host_port not in self.remote_udp_table:
                loop = asyncio.get_event_loop()
                task = loop.create_datagram_endpoint(
                    lambda: RemoteUDP(self, local_host_port, self.config),
                    local_addr=("0.0.0.0", 0),
                )
                _, remote_udp = await asyncio.wait_for(task, 5)
                self.remote_udp_table[local_host_port] = remote_udp
            remote_udp = self.remote_udp_table[local_host_port]
            remote_udp.write(data[header_length:], (DST_ADDR, DST_PORT))
        except Exception as e:
            error_logger.warning(f"{e} during the relay request from {local_host_port}")
            return

    def close(self):
        if self.is_closing:
            return
        self.is_closing = True
        self.transport and self.transport.close()
        for local_host_port in self.remote_udp_table:
            self.remote_udp_table[local_host_port].close()

        self.config.ACCESS_LOG and access_logger.debug(
            f"Local UDP endpoint closed {self.sockname}"
        )


class RemoteUDP(asyncio.DatagramProtocol):
    def __init__(self, local_udp, local_host_port, config: Config):
        self.local_udp = local_udp
        self.local_host_port = local_host_port
        self.config = config
        self.transport = None
        self.sockname = None
        self.is_closing = False

    def connection_made(self, transport) -> None:
        self.transport = transport
        self.sockname = transport.get_extra_info("sockname")

        self.config.ACCESS_LOG and access_logger.debug(
            f"Remote UDP endpoint made {self.sockname}"
        )

    def write(self, data, host_port):
        if not self.transport.is_closing():
            self.transport.sendto(data, host_port)

    @staticmethod
    def gen_udp_reply_header(remote_host_port: Tuple[str, int]):
        RSV, FRAG = b"\x00\x00", b"\x00"
        remote_host, remote_port = remote_host_port
        ATYP = get_atyp_from_host(remote_host)
        if ATYP == Atyp.IPV4:
            DST_ADDR = inet_pton(AF_INET, remote_host)
        elif ATYP == Atyp.IPV6:
            DST_ADDR = inet_pton(AF_INET6, remote_host)
        elif ATYP == Atyp.DOMAIN:
            DST_ADDR = len(remote_host).to_bytes(1, "big") + remote_host.encode("UTF-8")
        else:
            raise HeaderParseError()
        ATYP = ATYP.to_bytes(1, "big")
        DST_PORT = remote_port.to_bytes(2, "big")
        return RSV + FRAG + ATYP + DST_ADDR + DST_PORT

    def datagram_received(self, data: bytes, remote_host_port: Tuple[str, int]) -> None:
        try:
            header = self.gen_udp_reply_header(remote_host_port)
            self.local_udp.write(header + data, self.local_host_port)
        except Exception as e:
            error_logger.warning(
                f"{e} during the relay response from {remote_host_port}"
            )
            return

    def close(self):
        if self.is_closing:
            return
        self.is_closing = True
        self.transport and self.transport.close()
        self.local_udp = None

        self.config.ACCESS_LOG and access_logger.debug(
            f"Remote UDP endpoint closed {self.sockname}"
        )

    def error_received(self, exc):
        self.close()

    def connection_lost(self, exc):
        self.close()
