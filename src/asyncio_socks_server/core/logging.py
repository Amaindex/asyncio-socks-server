from __future__ import annotations

import logging

from .types import Address

FORMAT = "%(asctime)s | %(levelname)-8s | %(message)s"


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        format=FORMAT,
        level=getattr(logging, level.upper()),
        force=True,
    )


def get_logger() -> logging.Logger:
    return logging.getLogger("asyncio_socks_server")


def fmt_addr(addr: Address) -> str:
    return str(addr)


def fmt_connection(src: Address, dst: Address) -> str:
    return f"{src} → {dst}"


def fmt_bytes(n: int) -> str:
    if n < 1024:
        return f"{n}B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f}KB"
    return f"{n / (1024 * 1024):.1f}MB"
