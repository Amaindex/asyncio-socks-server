"""Tests for Connection dataclass."""

import asyncio

from asyncio_socks_server.core.types import Address
from asyncio_socks_server.server.connection import Connection


class TestConnection:
    async def test_dataclass_fields(self):
        reader = asyncio.StreamReader()
        writer = None  # Writer not needed for this test
        addr = Address("127.0.0.1", 1080)
        conn = Connection(reader=reader, writer=writer, address=addr)
        assert conn.reader is reader
        assert conn.writer is writer
        assert conn.address == addr

    async def test_address_type(self):
        reader = asyncio.StreamReader()
        conn = Connection(reader=reader, writer=None, address=Address("::1", 443))
        assert isinstance(conn.address, Address)
        assert conn.address.host == "::1"
        assert conn.address.port == 443
