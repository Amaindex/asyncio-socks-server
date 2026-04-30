import asyncio
import ipaddress
import struct

from asyncio_socks_server.core.address import encode_address
from asyncio_socks_server.core.types import Address


async def socks5_connect(
    proxy: Address,
    target: Address,
    auth: tuple[str, str] | None = None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await asyncio.open_connection(proxy.host, proxy.port)

    writer.write(b"\x05\x01\x02" if auth else b"\x05\x01\x00")
    await writer.drain()

    resp = await reader.readexactly(2)
    assert resp[0] == 0x05

    if auth is None:
        assert resp[1] == 0x00
    else:
        assert resp[1] == 0x02
        username, password = auth
        uname = username.encode()
        passwd = password.encode()
        writer.write(
            b"\x01"
            + len(uname).to_bytes(1, "big")
            + uname
            + len(passwd).to_bytes(1, "big")
            + passwd
        )
        await writer.drain()
        assert await reader.readexactly(2) == b"\x01\x00"

    writer.write(b"\x05\x01\x00" + encode_address(target.host, target.port))
    await writer.drain()
    return reader, writer


async def read_socks_reply(reader: asyncio.StreamReader) -> bytes:
    reply = await reader.readexactly(3)
    atyp = (await reader.readexactly(1))[0]
    if atyp == 0x01:
        await reader.readexactly(4 + 2)
    elif atyp == 0x04:
        await reader.readexactly(16 + 2)
    elif atyp == 0x03:
        length = (await reader.readexactly(1))[0]
        await reader.readexactly(length + 2)
    return reply


async def open_udp_associate(
    proxy: Address,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, Address]:
    reader, writer = await asyncio.open_connection(proxy.host, proxy.port)

    writer.write(b"\x05\x01\x00")
    await writer.drain()
    assert await reader.readexactly(2) == b"\x05\x00"

    writer.write(b"\x05\x03\x00" + encode_address("0.0.0.0", 0))
    await writer.drain()

    reply = await reader.readexactly(3)
    assert reply[1] == 0x00

    atyp = (await reader.readexactly(1))[0]
    if atyp == 0x01:
        bind_host = ipaddress.IPv4Address(await reader.readexactly(4)).compressed
    elif atyp == 0x04:
        bind_host = str(ipaddress.IPv6Address(await reader.readexactly(16)))
    else:
        length = (await reader.readexactly(1))[0]
        bind_host = (await reader.readexactly(length)).decode("ascii")

    bind_port = struct.unpack("!H", await reader.readexactly(2))[0]
    return reader, writer, Address(bind_host, bind_port)
