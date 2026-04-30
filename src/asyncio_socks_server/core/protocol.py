from __future__ import annotations

import asyncio
import ipaddress
import struct

from .types import Address, Cmd


class ProtocolError(Exception):
    pass


def parse_method_selection(data: bytes) -> tuple[int, set[int]]:
    if len(data) < 2:
        raise ProtocolError("method selection too short")
    VER = data[0]
    NMETHODS = data[1]
    if VER != 0x05:
        raise ProtocolError(f"unsupported SOCKS version: {VER}")
    METHODS = set(data[2 : 2 + NMETHODS])
    return VER, METHODS


def build_method_reply(method: int) -> bytes:
    VER = b"\x05"
    METHOD = method.to_bytes(1, "big")
    return VER + METHOD


async def parse_username_password(
    reader: asyncio.StreamReader,
) -> tuple[str, str]:
    VER = (await reader.readexactly(1))[0]
    if VER != 0x01:
        raise ProtocolError(f"unsupported auth version: {VER}")
    ULEN = (await reader.readexactly(1))[0]
    UNAME = (await reader.readexactly(ULEN)).decode("utf-8")
    PLEN = (await reader.readexactly(1))[0]
    PASSWD = (await reader.readexactly(PLEN)).decode("utf-8")
    return UNAME, PASSWD


def build_auth_reply(success: bool) -> bytes:
    VER = b"\x01"
    STATUS = b"\x00" if success else b"\x01"
    return VER + STATUS


async def parse_request(reader: asyncio.StreamReader) -> tuple[Cmd, Address]:
    VER, CMD, RSV, ATYP_BYTE = await reader.readexactly(4)
    if VER != 0x05:
        raise ProtocolError(f"unsupported SOCKS version: {VER}")
    try:
        cmd = Cmd(CMD)
    except ValueError:
        raise ProtocolError(f"unsupported command: {CMD}") from None

    if ATYP_BYTE == 0x01:  # IPv4
        host = ipaddress.IPv4Address(await reader.readexactly(4)).compressed
    elif ATYP_BYTE == 0x04:  # IPv6
        host = ipaddress.IPv6Address(await reader.readexactly(16)).compressed
    elif ATYP_BYTE == 0x03:  # Domain
        length = (await reader.readexactly(1))[0]
        host = (await reader.readexactly(length)).decode("ascii")
    else:
        raise ProtocolError(f"unsupported ATYP: {ATYP_BYTE}")

    DST_PORT = struct.unpack("!H", await reader.readexactly(2))[0]
    return cmd, Address(host, DST_PORT)


def parse_udp_header(data: bytes) -> tuple[Address, int, bytes]:
    """Parse SOCKS5 UDP request header.

    Returns (dst_address, header_length, payload).
    """
    if len(data) < 4:
        raise ProtocolError("UDP header too short")
    # RSV(2) + FRAG(1) skipped — we don't support fragmentation
    ATYP_BYTE = data[3]

    if ATYP_BYTE == 0x01:
        if len(data) < 10:
            raise ProtocolError("UDP header truncated (IPv4)")
        host = ipaddress.IPv4Address(data[4:8]).compressed
        DST_PORT = struct.unpack("!H", data[8:10])[0]
        header_length = 10
    elif ATYP_BYTE == 0x04:
        if len(data) < 22:
            raise ProtocolError("UDP header truncated (IPv6)")
        host = ipaddress.IPv6Address(data[4:20]).compressed
        DST_PORT = struct.unpack("!H", data[20:22])[0]
        header_length = 22
    elif ATYP_BYTE == 0x03:
        length = data[4]
        if len(data) < 5 + length + 2:
            raise ProtocolError("UDP header truncated (domain)")
        host = data[5 : 5 + length].decode("ascii")
        DST_PORT = struct.unpack("!H", data[5 + length : 5 + length + 2])[0]
        header_length = 5 + length + 2
    else:
        raise ProtocolError(f"unsupported ATYP: {ATYP_BYTE}")

    return Address(host, DST_PORT), header_length, data[header_length:]


def build_udp_header(address: Address) -> bytes:
    RSV = b"\x00\x00"
    FRAG = b"\x00"
    from .address import encode_address

    return RSV + FRAG + encode_address(address.host, address.port)
