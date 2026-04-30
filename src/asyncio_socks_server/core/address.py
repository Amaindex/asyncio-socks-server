from __future__ import annotations

import asyncio
import ipaddress
import struct
from ipaddress import IPv4Address, IPv6Address

from .types import Address, Atyp, Rep


def detect_atyp(host: str) -> Atyp:
    try:
        IPv4Address(host)
        return Atyp.IPV4
    except ValueError:
        pass
    try:
        IPv6Address(host)
        return Atyp.IPV6
    except ValueError:
        pass
    return Atyp.DOMAIN


def encode_address(host: str, port: int) -> bytes:
    atyp = detect_atyp(host)
    if atyp == Atyp.IPV4:
        ADDR = ipaddress.IPv4Address(host).packed
    elif atyp == Atyp.IPV6:
        ADDR = ipaddress.IPv6Address(host).packed
    else:
        encoded = host.encode("ascii")
        ADDR = bytes([len(encoded)]) + encoded
    ATYP = atyp.to_bytes(1, "big")
    PORT = struct.pack("!H", port)
    return ATYP + ADDR + PORT


async def decode_address(reader: asyncio.StreamReader) -> Address:
    ATYP = Atyp((await reader.readexactly(1))[0])
    if ATYP == Atyp.IPV4:
        DST_ADDR = ipaddress.IPv4Address(await reader.readexactly(4)).compressed
    elif ATYP == Atyp.IPV6:
        DST_ADDR = ipaddress.IPv6Address(await reader.readexactly(16)).compressed
    elif ATYP == Atyp.DOMAIN:
        length = (await reader.readexactly(1))[0]
        DST_ADDR = (await reader.readexactly(length)).decode("ascii")
    else:
        raise ValueError(f"unsupported ATYP: {ATYP}")
    DST_PORT = struct.unpack("!H", await reader.readexactly(2))[0]
    return Address(DST_ADDR, DST_PORT)


def encode_reply(
    rep: Rep,
    bind_host: str = "0.0.0.0",
    bind_port: int = 0,
) -> bytes:
    VER = b"\x05"
    REP = rep.to_bytes(1, "big")
    RSV = b"\x00"
    return VER + REP + RSV + encode_address(bind_host, bind_port)
