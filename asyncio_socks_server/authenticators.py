from asyncio.streams import StreamReader
from asyncio.transports import WriteTransport
from typing import Dict

from asyncio_socks_server.config import Config
from asyncio_socks_server.exceptions import (
    AuthenticationError,
    NoVersionAllowed,
)
from asyncio_socks_server.values import AuthMethods


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
        if self.METHOD in methods:
            return self.METHOD
        else:
            return 0xFF

    async def authenticate(self):
        raise NotImplementedError


class NoAuthenticator(BaseAuthenticator):

    METHOD = AuthMethods.NO_AUTH

    async def authenticate(self):
        pass


class PasswordAuthenticator(BaseAuthenticator):

    METHOD = AuthMethods.PASSWORD_AUTH

    def verify_user(self, username: str, password: str) -> bool:
        try:
            return (username, password) in self._config.USERS.items()
        except AttributeError:
            raise AttributeError("Can not parse Config.USERS") from None

    async def authenticate(self):
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


AUTHENTICATORS_CLS_LIST = [NoAuthenticator, PasswordAuthenticator]
