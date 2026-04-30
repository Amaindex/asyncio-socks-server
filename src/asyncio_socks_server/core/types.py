from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, StrEnum
from typing import Literal


class Rep(IntEnum):
    """RFC 1928 reply codes."""

    SUCCEEDED = 0x00
    GENERAL_FAILURE = 0x01
    CONNECTION_NOT_ALLOWED = 0x02
    NETWORK_UNREACHABLE = 0x03
    HOST_UNREACHABLE = 0x04
    CONNECTION_REFUSED = 0x05
    TTL_EXPIRED = 0x06
    COMMAND_NOT_SUPPORTED = 0x07
    ADDRESS_TYPE_NOT_SUPPORTED = 0x08


class AuthMethod(IntEnum):
    """SOCKS5 authentication methods."""

    NO_AUTH = 0x00
    USERNAME_PASSWORD = 0x02
    NO_ACCEPTABLE = 0xFF


class Cmd(IntEnum):
    """SOCKS5 commands."""

    CONNECT = 0x01
    UDP_ASSOCIATE = 0x03


class Atyp(IntEnum):
    """SOCKS5 address types."""

    IPV4 = 0x01
    DOMAIN = 0x03
    IPV6 = 0x04


class Direction(StrEnum):
    """Data flow direction."""

    UPSTREAM = "upstream"
    DOWNSTREAM = "downstream"


@dataclass(frozen=True)
class Address:
    host: str
    port: int

    def __str__(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass
class Flow:
    """Per-connection context carried through the hook lifecycle."""

    id: int
    src: Address
    dst: Address
    protocol: Literal["tcp", "udp"]
    started_at: float  # time.monotonic()
    bytes_up: int = 0  # TCP: post-addon; UDP: raw payload (no addon pipeline)
    bytes_down: int = 0
