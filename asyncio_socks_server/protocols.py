import asyncio
import ipaddress
import itertools
import socket
from asyncio.streams import StreamReader
from socket import AF_INET, AF_INET6, inet_ntop, inet_pton
from typing import Optional, Tuple

from asyncio_socks_server.authenticators import AUTHENTICATORS_CLS_LIST, NoAuthenticator
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
    NoAddressAllowed
)
from asyncio_socks_server.logger import access_logger, error_logger, logger
from asyncio_socks_server.utils import get_socks_atyp_from_host
from asyncio_socks_server.values import SocksAtyp, SocksCommand, Socks5Rep, Socks4Rep


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
        self.negotiate_task = None
        self.is_closing = False
        self.__init_authenticator_cls()

    def __init_authenticator_cls(self):
        for cls in AUTHENTICATORS_CLS_LIST:
            if cls.METHOD == self.config.AUTH_METHOD:
                self.authenticator_cls = cls

    async def wf_readexactly(self, n):
        return await asyncio.wait_for(
            self.stream_reader.readexactly(n), timeout=self.config.SOCKET_TIMEOUT
        )

    async def wf_readuntil(self, s):
        return await asyncio.wait_for(
            self.stream_reader.readuntil(s), timeout=self.config.SOCKET_TIMEOUT
        )

    def write(self, data):
        if not self.transport.is_closing():
            self.transport.write(data)

    def connection_made(self, transport):
        self.transport = transport
        self.peername = transport.get_extra_info("peername")
        self.stream_reader.set_transport(transport)
        loop = asyncio.get_event_loop()
        self.negotiate_task = loop.create_task(self.negotiate_misc())
        self.stage = self.STAGE_NEGOTIATE

        self.config.ACCESS_LOG and access_logger.debug(
            f"Made LocalTCP connection from {self.peername}"
        )

    async def negotiate_misc(self):
        try:
            # Guess version.
            VER = int.from_bytes(await self.wf_readexactly(1), "big")
            await self.validate(VER)
            if VER == 5:
                await self.negotiate_socks5()
            elif VER == 4 and self.authenticator_cls == NoAuthenticator:
                await self.negotiate_socks4()
            else:
                raise NoVersionAllowed(f"Received unsupported socks version: {VER}")
        except (SocksException, ConnectionError, ValueError, OSError) as e:
            error_logger.warning(f"{e} during the negotiation with {self.peername}")
            self.close()

    async def validate(self, ver) -> None:
        if self.config.NETWORKS is None or len(self.config.NETWORKS) <= 0:
            return
        ip_addr = ipaddress.ip_address(self.peername[0])
        for network in self.config.NETWORKS:
            net = ipaddress.ip_network(network, strict=False)
            if ip_addr in net:
                return
        if ver == 5:
            self.transport.write(self.gen_socks5_reply(Socks5Rep.ADDRESS_NOT_ALLOWED))
        elif ver == 4:
            self.transport.write(self.gen_socks4_reply(Socks4Rep.ADDRESS_NOT_ALLOWED))
        raise NoAddressAllowed(f"Address {self.peername[0]} is not allowed") from None

    @staticmethod
    def gen_socks5_reply(
            rep: Socks5Rep,
            bind_host: str = "0.0.0.0",
            bind_port: int = 0,
    ) -> bytes:
        """Generate reply for socks5 negotiation."""

        VER, RSV = b"\x05", b"\x00"
        ATYP = get_socks_atyp_from_host(bind_host)
        if ATYP == SocksAtyp.IPV4:
            BND_ADDR = inet_pton(AF_INET, bind_host)
        elif ATYP == SocksAtyp.IPV6:
            BND_ADDR = inet_pton(AF_INET6, bind_host)
        else:
            BND_ADDR = len(bind_host).to_bytes(2, "big") + bind_host.encode("UTF-8")
        REP = rep.to_bytes(1, "big")
        ATYP = ATYP.to_bytes(1, "big")
        BND_PORT = int(bind_port).to_bytes(2, "big")
        return VER + REP + RSV + ATYP + BND_ADDR + BND_PORT

    async def negotiate_socks5(self):
        """Negotiate with the client. Find more detail in RFC1928."""

        # Step 1.1
        # The client sends a (version identifier and) method selection message:
        # +----+----------+----------+
        # |VER | NMETHODS | METHODS  |
        # +----+----------+----------+
        # | 1  |    1     | 1 to 255 |
        # +----+----------+----------+
        NMETHODS = int.from_bytes(await self.wf_readexactly(1), "big")
        METHODS = set(await self.wf_readexactly(NMETHODS))

        # Step 1.2
        # The server selects from one of the methods given in METHODS, and
        # sends a METHOD selection message:
        # +----+--------+
        # |VER | METHOD |
        # +----+--------+
        # | 1  |   1    |
        # +----+--------+
        authenticator = self.authenticator_cls(
            self.stream_reader, self.transport, self.config
        )
        METHOD = authenticator.select_method(METHODS)
        self.write(b"\x05" + METHOD.to_bytes(1, "big"))
        if METHOD == 0xFF:
            raise NoAuthMethodAllowed("No authentication method is available")

        # Step 1.3
        # The client and the server enter a method-specific sub-negotiation.
        await authenticator.authenticate()

        # Step 2.1
        # The client sends a socks request formed as follows:
        # +----+-----+-------+------+----------+----------+
        # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        # +----+-----+-------+------+----------+----------+
        # | 1  |  1  | X'00' |  1   | Variable |    2     |
        # +----+-----+-------+------+----------+----------+
        VER, CMD, RSV, ATYP = await self.wf_readexactly(4)
        if ATYP == SocksAtyp.IPV4:
            DST_ADDR = inet_ntop(AF_INET, await self.wf_readexactly(4))
        elif ATYP == SocksAtyp.DOMAIN:
            domain_len = int.from_bytes(await self.wf_readexactly(1), "big")
            DST_ADDR = (await self.wf_readexactly(domain_len)).decode()
        elif ATYP == SocksAtyp.IPV6:
            DST_ADDR = inet_ntop(AF_INET6, await self.wf_readexactly(16))
        else:
            self.write(self.gen_socks5_reply(Socks5Rep.ADDRESS_TYPE_NOT_SUPPORTED))
            raise NoAtypAllowed(f"Received unsupported ATYP value: {ATYP}")
        DST_PORT = int.from_bytes(await self.wf_readexactly(2), "big")

        # Step 2.2
        # The server handles the command and returns a reply formed as follows:
        # +----+-----+-------+------+----------+----------+
        # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        # +----+-----+-------+------+----------+----------+
        # | 1  |  1  | X'00' |  1   | Variable |    2     |
        # +----+-----+-------+------+----------+----------+
        if CMD == SocksCommand.CONNECT:
            await self.socks5_connect(DST_ADDR, DST_PORT)
        elif CMD == SocksCommand.UDP_ASSOCIATE:
            await self.socks5_udp_associate(DST_ADDR, DST_PORT)
        else:
            self.write(self.gen_socks5_reply(Socks5Rep.COMMAND_NOT_SUPPORTED))
            raise NoCommandAllowed(f"Unsupported CMD value: {CMD}")

    async def socks5_connect(self, dst_addr, dst_port):
        try:
            loop = asyncio.get_event_loop()
            task = loop.create_connection(
                lambda: RemoteTCP(self, self.config), dst_addr, dst_port
            )
            remote_tcp_transport, remote_tcp = await asyncio.wait_for(task, 10)
        except ConnectionRefusedError:
            self.write(self.gen_socks5_reply(Socks5Rep.CONNECTION_REFUSED))
            raise CommandExecError("Connection was refused") from None
        except socket.gaierror:
            self.write(self.gen_socks5_reply(Socks5Rep.HOST_UNREACHABLE))
            raise CommandExecError("Host is unreachable") from None
        except Exception:
            self.write(self.gen_socks5_reply(Socks5Rep.GENERAL_SOCKS_SERVER_FAILURE))
            raise CommandExecError("General socks server failure occurred")
        else:
            self.remote_tcp = remote_tcp
            bind_addr, bind_port = remote_tcp_transport.get_extra_info("sockname")
            self.write(self.gen_socks5_reply(Socks5Rep.SUCCEEDED, bind_addr, bind_port))
            self.stage = self.STAGE_CONNECT

            self.config.ACCESS_LOG and access_logger.info(
                f"Established TCP stream between"
                f" {self.peername} and {self.remote_tcp.peername}"
            )

    async def socks5_udp_associate(self, dst_addr, dst_port):
        try:
            loop = asyncio.get_event_loop()
            task = loop.create_datagram_endpoint(
                lambda: LocalUDP((dst_addr, dst_port), self.config),
                local_addr=("0.0.0.0", 0),
            )
            local_udp_transport, local_udp = await asyncio.wait_for(task, 10)
        except Exception:
            self.write(self.gen_socks5_reply(Socks5Rep.GENERAL_SOCKS_SERVER_FAILURE))
            raise CommandExecError("General socks server failure occurred")
        else:
            self.local_udp = local_udp
            bind_addr, bind_port = local_udp_transport.get_extra_info("sockname")
            self.write(self.gen_socks5_reply(Socks5Rep.SUCCEEDED, bind_addr, bind_port))
            self.stage = self.STAGE_UDP_ASSOCIATE

            self.config.ACCESS_LOG and access_logger.info(
                f"Established UDP relay for {self.peername} "
                f"at {bind_addr, bind_port}"
            )

    @staticmethod
    def gen_socks4_reply(
            rep: Socks4Rep,
            dst_ip: str = "0.0.0.0",
            dst_port: int = 0,
    ) -> bytes:
        """Generate reply for socks4 negotiation."""

        VER = b"\x00"
        CD = rep.to_bytes(1, "big")
        DST_IP = inet_pton(AF_INET, dst_ip)
        DST_PORT = int(dst_port).to_bytes(2, "big")
        return VER + CD + DST_PORT + DST_IP

    async def negotiate_socks4(self):
        CMD = int.from_bytes(await self.wf_readexactly(1), "big")
        DST_PORT = int.from_bytes(await self.wf_readexactly(2), "big")
        DST_ADDR = inet_ntop(AF_INET, await self.wf_readexactly(4))
        USERID = (await self.wf_readuntil(b"\x00"))[:-1]

        socks4a_placeholders = ipaddress.IPv4Network("0.0.0.0/24")
        if ipaddress.ip_address(DST_ADDR) in socks4a_placeholders:
            DST_ADDR = (await self.wf_readuntil(b"\x00"))[:-1].decode()

        if CMD == SocksCommand.CONNECT:
            await self.socks4_connect(DST_ADDR, DST_PORT)
        else:
            self.write(self.gen_socks4_reply(Socks4Rep.REQUEST_REJECTED_OR_FAILED))
            raise NoCommandAllowed(f"Unsupported CMD value: {CMD}")

    async def socks4_connect(self, dst_addr, dst_port):

        try:
            loop = asyncio.get_event_loop()
            task = loop.create_connection(
                lambda: RemoteTCP(self, self.config), dst_addr, dst_port
            )
            remote_tcp_transport, remote_tcp = await asyncio.wait_for(task, 10)
        except Exception:
            self.write(self.gen_socks4_reply(Socks4Rep.REQUEST_REJECTED_OR_FAILED))
            raise CommandExecError("Request was rejected or failed")
        else:
            self.remote_tcp = remote_tcp
            self.write(self.gen_socks4_reply(Socks4Rep.REQUEST_GRANTED))
            self.stage = self.STAGE_CONNECT

            self.config.ACCESS_LOG and access_logger.info(
                f"Established TCP stream between"
                f" {self.peername} and {self.remote_tcp.peername}"
            )

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

    def pause_writing(self) -> None:
        try:
            self.remote_tcp.transport.pause_reading()
        except AttributeError:
            pass

    def resume_writing(self) -> None:
        self.remote_tcp.transport.resume_reading()

    def connection_lost(self, exc: Optional[Exception]) -> None:
        self.close()

    def close(self):
        if self.is_closing:
            return
        self.stage = self.STAGE_DESTROY
        self.is_closing = True

        self.negotiate_task and self.negotiate_task.cancel()
        self.transport and self.transport.close()
        self.remote_tcp and self.remote_tcp.close()
        self.local_udp and self.local_udp.close()

        self.config.ACCESS_LOG and access_logger.debug(
            f"Closed LocalTCP connection from {self.peername}"
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
            f"Made RemoteTCP connection to {self.peername}"
        )

    def data_received(self, data):
        self.local_tcp.write(data)

    def eof_received(self):
        self.close()

    def pause_writing(self) -> None:
        try:
            self.local_tcp.transport.pause_reading()
        except AttributeError:
            pass

    def resume_writing(self) -> None:
        self.local_tcp.transport.resume_reading()

    def connection_lost(self, exc):
        self.close()

    def close(self):
        if self.is_closing:
            return
        self.is_closing = True
        self.transport and self.transport.close()
        self.local_tcp.close()

        self.config.ACCESS_LOG and access_logger.debug(
            f"Closed RemoteTCP connection to {self.peername}"
        )


class LocalUDP(asyncio.DatagramProtocol):
    def __init__(self, host_port_limit: Tuple[str, int], config: Config):
        self.host_port_limit = host_port_limit
        self.config = config
        self.transport = None
        self.sockname = None
        self.udp_map = {}  # local_host_port -> remote_udp
        self.is_closing = False

    def write(self, data, port_addr):
        if not self.transport.is_closing():
            self.transport.sendto(data, port_addr)

    def connection_made(self, transport) -> None:
        self.transport = transport
        self.sockname = transport.get_extra_info("sockname")

        self.config.ACCESS_LOG and access_logger.debug(
            f"Made LocalUDP endpoint at {self.sockname}"
        )

    @staticmethod
    def parse_udp_request_header(data: bytes):
        """Parse the header of UDP request.

        Each UDP datagram carries a UDP request header formed as follows: ::

            +----+------+------+----------+----------+----------+
            |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
            +----+------+------+----------+----------+----------+
            | 2  |  1   |  1   | Variable |    2     | Variable |
            +----+------+------+----------+----------+----------+

        :param data: UDP datagram
        :return: A tuple containing header fields and header length
        :raise HeaderParseError: If parsing fails
        """

        length = 0
        RSV = data[length: length + 2]
        length += 2
        FRAG = data[length: length + 1]
        if int.from_bytes(FRAG, "big") != 0:
            raise HeaderParseError("Received unsupported FRAG value")
        length += 1
        ATYP = int.from_bytes(data[length: length + 1], "big")
        length += 1
        if ATYP == SocksAtyp.IPV4:
            ipv4 = data[length: length + 4]
            DST_ADDR = inet_ntop(AF_INET, ipv4)
            length += 4
        elif ATYP == SocksAtyp.DOMAIN:
            addr_len = int.from_bytes(data[length: length + 1], byteorder="big")
            length += 1
            DST_ADDR = data[length: length + addr_len].decode()
            length += addr_len
        elif ATYP == SocksAtyp.IPV6:
            ipv6 = data[length: length + 16]
            DST_ADDR = inet_ntop(AF_INET6, ipv6)
            length += 16
        else:
            raise HeaderParseError(f"Received unsupported ATYP value: {ATYP}")
        DST_PORT = int.from_bytes(data[length: length + 2], "big")
        length += 2
        if length > len(data):
            raise HeaderParseError("Header is too short")
        return RSV, FRAG, ATYP, DST_ADDR, DST_PORT, length

    def datagram_received(self, data: bytes, local_host_port: Tuple[str, int]):
        cond1 = self.host_port_limit in itertools.product(
            ("0.0.0.0", "::", local_host_port[0]), (0, local_host_port[1])
        )
        cond2 = self.config.STRICT == False
        if not cond1 and not cond2:
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

            if local_host_port not in self.udp_map:
                loop = asyncio.get_event_loop()
                task = loop.create_datagram_endpoint(
                    lambda: RemoteUDP(self, local_host_port, self.config),
                    local_addr=("0.0.0.0", 0),
                )
                _, remote_udp = await asyncio.wait_for(task, 5)
                self.udp_map[local_host_port] = remote_udp
            remote_udp = self.udp_map[local_host_port]
            remote_udp.write(data[header_length:], (DST_ADDR, DST_PORT))
        except Exception as e:
            error_logger.warning(
                f"{e} during relaying the request from {local_host_port}"
            )
            return

    def close(self):
        if self.is_closing:
            return
        self.is_closing = True
        self.transport and self.transport.close()
        for local_host_port in self.udp_map:
            self.udp_map[local_host_port].close()

        self.config.ACCESS_LOG and access_logger.debug(
            f"Closed LocalUDP endpoint at {self.sockname}"
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
            f"Made RemoteUDP endpoint at {self.sockname}"
        )

    def write(self, data, host_port):
        if not self.transport.is_closing():
            self.transport.sendto(data, host_port)

    @staticmethod
    def gen_udp_reply_header(remote_host_port: Tuple[str, int]):
        """Generate the header of UDP reply.

        When a UDP relay server receives a reply datagram from a remote
        host, it MUST encapsulate that datagram using the UDP request
        header: ::

            +----+------+------+----------+----------+----------+
            |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
            +----+------+------+----------+----------+----------+
            | 2  |  1   |  1   | Variable |    2     | Variable |
            +----+------+------+----------+----------+----------+

        and any authentication-method-dependent encapsulation.

        :param remote_host_port: A tuple of host and port
        :return: The bytes of the generated header
        """

        RSV, FRAG = b"\x00\x00", b"\x00"
        remote_host, remote_port = remote_host_port
        ATYP = get_socks_atyp_from_host(remote_host)
        if ATYP == SocksAtyp.IPV4:
            DST_ADDR = inet_pton(AF_INET, remote_host)
        elif ATYP == SocksAtyp.IPV6:
            DST_ADDR = inet_pton(AF_INET6, remote_host)
        else:  # ATYP == SocksAtyp.DOMAIN
            DST_ADDR = len(remote_host).to_bytes(1, "big") + remote_host.encode("UTF-8")
        ATYP = ATYP.to_bytes(1, "big")
        DST_PORT = remote_port.to_bytes(2, "big")
        return RSV + FRAG + ATYP + DST_ADDR + DST_PORT

    def datagram_received(self, data: bytes, remote_host_port: Tuple[str, int]) -> None:
        try:
            header = self.gen_udp_reply_header(remote_host_port)
            self.local_udp.write(header + data, self.local_host_port)
        except Exception as e:
            error_logger.warning(
                f"{e} during relaying the response from {remote_host_port}"
            )
            return

    def close(self):
        if self.is_closing:
            return
        self.is_closing = True
        self.transport and self.transport.close()
        self.local_udp = None

        self.config.ACCESS_LOG and access_logger.debug(
            f"Closed RemoteUDP endpoint at {self.sockname}"
        )

    def error_received(self, exc):
        self.close()

    def connection_lost(self, exc):
        self.close()
