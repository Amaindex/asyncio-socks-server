from __future__ import annotations

import asyncio
from dataclasses import dataclass

from asyncio_socks_server.core.types import Address


@dataclass
class Connection:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    address: Address
