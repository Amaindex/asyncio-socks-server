from __future__ import annotations

import asyncio
import struct

from asyncio_socks_server.core.address import decode_address, encode_address
from asyncio_socks_server.core.types import Address


async def encode_udp_frame(address: Address, data: bytes) -> bytes:
    """Encode a UDP datagram as a TCP frame.

    Frame format: [4-byte length][ATYP+ADDR+PORT][payload]
    """
    addr_bytes = encode_address(address.host, address.port)
    payload = addr_bytes + data
    length = struct.pack("!I", len(payload))
    return length + payload


async def read_udp_frame(
    reader: asyncio.StreamReader,
) -> tuple[Address, bytes]:
    """Read a UDP-over-TCP frame from a stream.

    Returns (target_address, payload).
    """
    length_bytes = await reader.readexactly(4)
    length = struct.unpack("!I", length_bytes)[0]
    payload = await reader.readexactly(length)

    # Parse address from the beginning of payload
    atyp_byte = payload[0]
    if atyp_byte == 0x01:  # IPv4
        addr_len = 1 + 4 + 2  # ATYP + IPv4 + PORT
    elif atyp_byte == 0x04:  # IPv6
        addr_len = 1 + 16 + 2
    elif atyp_byte == 0x03:  # Domain
        domain_len = payload[1]
        addr_len = 1 + 1 + domain_len + 2
    else:
        raise ValueError(f"unsupported ATYP: {atyp_byte}")

    addr_payload = payload[:addr_len]
    data = payload[addr_len:]

    # Decode address
    addr_reader = asyncio.StreamReader()
    addr_reader.feed_data(addr_payload)
    addr_reader.feed_eof()
    address = await decode_address(addr_reader)

    return address, data
