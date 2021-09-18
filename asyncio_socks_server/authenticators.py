from asyncio.streams import StreamReader
from asyncio.transports import WriteTransport

from asyncio_socks_server.config import Config
from asyncio_socks_server.exceptions import AuthenticationError, NoVersionAllowed
from asyncio_socks_server.values import SocksAuthMethod


class BaseAuthenticator:

    METHOD: int

    def __init__(
        self,
        stream_reader: StreamReader,
        write_transport: WriteTransport,
        config: Config,
    ):
        self._stream_reader = stream_reader
        self._write_transport = write_transport
        self._config = config

    def select_method(self, methods: set) -> int:
        """Select a available method from a set

        Possible values of the set include:
        * X'00' NO AUTHENTICATION REQUIRED
        * X'01' GSSAPI
        * X'02' USERNAME/PASSWORD
        * X'03' to X'7F' IANA ASSIGNED
        * X'80' to X'FE' RESERVED FOR PRIVATE METHODS

        :param methods: The methods set provided by client
        :return: Method of this class if it's in param methods, else 0xFF to represent
            no methods is available.
        """

        if self.METHOD in methods:
            return self.METHOD
        else:
            return 0xFF

    async def authenticate(self) -> None:
        """Authenticate the client based on the authentication method of this class

        :return: None if the authentication is successful
        :raise AuthenticationError: If authentication fails
        """

        raise NotImplementedError


class NoAuthenticator(BaseAuthenticator):

    METHOD = SocksAuthMethod.NO_AUTH

    async def authenticate(self):
        pass


class UPAuthenticator(BaseAuthenticator):
    """Username/Password Authentication for SOCKS V5. Find more detail in RFC1929."""

    METHOD = SocksAuthMethod.UP_AUTH

    def verify_user(self, username: str, password: str) -> bool:
        try:
            return (username, password) in self._config.USERS.items()
        except AttributeError:
            raise AttributeError("Can not parse Config.USERS") from None

    async def authenticate(self) -> None:
        """
        Once the SOCKS V5 server has started, and the client has selected the
        Username/Password Authentication protocol, the Username/Password
        sub-negotiation begins.

        This begins with the client producing a Username/Password request: ::

            +----+------+----------+------+----------+
            |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
            +----+------+----------+------+----------+
            | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
            +----+------+----------+------+----------+

        The server verifies the supplied UNAME and PASSWD, and sends the
        following response: ::

            +----+--------+
            |VER | STATUS |
            +----+--------+
            | 1  |   1    |
            +----+--------+

        A STATUS field of X'00' indicates success. If the server returns a
        `failure` (STATUS value other than X'00') status, it MUST close the
        connection.
        """

        # Some clients use 5 as the version number of the Username/Password
        # authentication request, so we allow it in non-strict mode.
        VER = await self._stream_reader.readexactly(1)
        cond1 = VER == b"\x01"
        cond2 = VER == b"\x05" and not self._config.STRICT
        if not (cond1 or cond2):
            self._write_transport.write(b"\x01\x01")
            raise AuthenticationError(
                f"Received unsupported user/password authentication version {VER}"
            )

        ULEN = int.from_bytes(await self._stream_reader.readexactly(1), "big")
        UNAME = (await self._stream_reader.readexactly(ULEN)).decode("ASCII")
        PLEN = int.from_bytes(await self._stream_reader.readexactly(1), "big")
        PASSWD = (await self._stream_reader.readexactly(PLEN)).decode("ASCII")
        if self.verify_user(UNAME, PASSWD):
            self._write_transport.write(b"\x01\x00")
        else:
            self._write_transport.write(b"\x01\x01")
            raise AuthenticationError("USERNAME or PASSWORD is uncorrected")


AUTHENTICATORS_CLS_LIST = [NoAuthenticator, UPAuthenticator]
