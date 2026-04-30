from __future__ import annotations

import asyncio
import socket
from itertools import zip_longest

from asyncio_socks_server.core.address import decode_address, encode_address
from asyncio_socks_server.core.protocol import ProtocolError
from asyncio_socks_server.core.types import Address, AuthMethod, Rep
from asyncio_socks_server.server.connection import Connection

HAPPY_EYEBALLS_DELAY = 0.25


async def connect(
    proxy_addr: Address,
    target_addr: Address,
    username: str | None = None,
    password: str | None = None,
) -> Connection:
    """Connect to target through a SOCKS5 proxy using Happy Eyeballs."""
    reader, writer = await _happy_eyeballs_connect(proxy_addr)

    try:
        await _negotiate(reader, writer, username, password)
        await _request_connect(reader, writer, target_addr)

        sock = writer.get_extra_info("socket")
        sockname = sock.getsockname() if sock else ("0.0.0.0", 0)
        return Connection(
            reader=reader,
            writer=writer,
            address=Address(sockname[0], sockname[1]),
        )
    except Exception:
        writer.close()
        raise


async def _happy_eyeballs_connect(
    addr: Address,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Happy Eyeballs-style fallback with staggered IPv6/IPv4 candidates."""
    loop = asyncio.get_running_loop()
    ipv4_hosts: list[str] = []
    ipv6_hosts: list[str] = []

    try:
        results = await loop.getaddrinfo(addr.host, addr.port, type=socket.SOCK_STREAM)
        for family, _, _, _, sockaddr in results:
            if family == socket.AF_INET6:
                ipv6_hosts.append(sockaddr[0])
            elif family == socket.AF_INET:
                ipv4_hosts.append(sockaddr[0])
    except socket.gaierror:
        ipv4_hosts = [addr.host]

    candidates: list[tuple[str, int]] = []
    for ipv6_host, ipv4_host in zip_longest(ipv6_hosts, ipv4_hosts):
        if ipv6_host is not None:
            candidates.append((ipv6_host, addr.port))
        if ipv4_host is not None:
            candidates.append((ipv4_host, addr.port))

    if not candidates:
        raise ConnectionError(f"cannot resolve {addr.host}")

    if len(candidates) == 1:
        return await asyncio.open_connection(candidates[0][0], candidates[0][1])

    pending: set[asyncio.Task[tuple[asyncio.StreamReader, asyncio.StreamWriter]]] = (
        set()
    )
    errors: list[BaseException] = []
    next_candidate = 0

    def start_next_candidate() -> None:
        nonlocal next_candidate
        if next_candidate >= len(candidates):
            return
        host, port = candidates[next_candidate]
        next_candidate += 1
        pending.add(loop.create_task(asyncio.open_connection(host, port)))

    async def cancel_pending() -> None:
        for task in pending:
            task.cancel()
        for task in pending:
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

    start_next_candidate()

    while pending:
        timeout = HAPPY_EYEBALLS_DELAY if next_candidate < len(candidates) else None
        done_tasks, pending_tasks = await asyncio.wait(
            pending, timeout=timeout, return_when=asyncio.FIRST_COMPLETED
        )
        pending = set(pending_tasks)

        if not done_tasks:
            start_next_candidate()
            continue

        for task in done_tasks:
            try:
                result = task.result()
            except Exception as exc:
                errors.append(exc)
            else:
                await cancel_pending()
                return result

        if not pending:
            start_next_candidate()

    message = f"all connection attempts failed to {addr.host}:{addr.port}"
    if errors:
        raise ConnectionError(message) from errors[0]
    raise ConnectionError(message)


async def _negotiate(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    username: str | None,
    password: str | None,
) -> None:
    if username and password:
        writer.write(b"\x05\x01\x02")
    else:
        writer.write(b"\x05\x01\x00")
    await writer.drain()

    resp = await reader.readexactly(2)
    if resp[0] != 0x05:
        raise ProtocolError(f"unsupported SOCKS version: {resp[0]}")

    if resp[1] == AuthMethod.NO_AUTH:
        return
    if resp[1] == AuthMethod.USERNAME_PASSWORD and username and password:
        uname = username.encode("utf-8")
        passwd = password.encode("utf-8")
        writer.write(
            b"\x01"
            + len(uname).to_bytes(1, "big")
            + uname
            + len(passwd).to_bytes(1, "big")
            + passwd
        )
        await writer.drain()
        auth_resp = await reader.readexactly(2)
        if auth_resp[1] != 0x00:
            raise ProtocolError("authentication failed")
    elif resp[1] == AuthMethod.NO_ACCEPTABLE:
        raise ProtocolError("no acceptable auth method")
    else:
        raise ProtocolError(f"unsupported auth method: {resp[1]}")


async def _request_connect(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    target: Address,
) -> None:
    writer.write(b"\x05\x01\x00" + encode_address(target.host, target.port))
    await writer.drain()

    reply = await reader.readexactly(3)
    if reply[0] != 0x05:
        raise ProtocolError(f"unsupported SOCKS version: {reply[0]}")
    if reply[1] != Rep.SUCCEEDED:
        raise ProtocolError(f"connect failed with rep={reply[1]:#04x}")

    # Read bound address
    await decode_address(reader)
