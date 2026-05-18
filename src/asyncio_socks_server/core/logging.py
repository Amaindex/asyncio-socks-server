from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from .types import Address

TEXT_FORMAT = "%(asctime)s | %(levelname)-8s | %(message)s"


class JsonFormatter(logging.Formatter):
    """Small JSON formatter for operators that prefer machine-readable logs."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, UTC)
            .isoformat()
            .replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, separators=(",", ":"))


def setup_logging(
    level: str = "INFO",
    *,
    log_format: str = "text",
    force: bool = False,
) -> None:
    if log_format == "json":
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        logging.basicConfig(
            level=getattr(logging, level.upper()),
            handlers=[handler],
            force=force,
        )
        return

    logging.basicConfig(
        format=TEXT_FORMAT,
        level=getattr(logging, level.upper()),
        force=force,
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


def fmt_event(event: str, **fields: Any) -> str:
    parts = [f"event={_fmt_value(event)}"]
    for key, value in fields.items():
        if value is None:
            continue
        parts.append(f"{key}={_fmt_value(value)}")
    return " ".join(parts)


def _fmt_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return f"{value:.3f}"
    text = str(value)
    if text == "":
        return '""'
    if all(ch.isalnum() or ch in "._:/@+-" for ch in text):
        return text
    return json.dumps(text, ensure_ascii=False, separators=(",", ":"))
