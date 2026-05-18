"""Tests for core logging module."""

import json
import logging

from asyncio_socks_server.core.logging import (
    fmt_addr,
    fmt_bytes,
    fmt_connection,
    fmt_event,
    get_logger,
    setup_logging,
)
from asyncio_socks_server.core.types import Address


class TestSetupLogging:
    def test_sets_level_debug(self):
        setup_logging("DEBUG", force=True)
        logger = get_logger()
        assert logger.parent.level == logging.DEBUG

    def test_sets_level_info(self):
        setup_logging("INFO", force=True)
        logger = get_logger()
        assert logger.parent.level == logging.INFO

    def test_sets_json_formatter(self):
        setup_logging("INFO", log_format="json", force=True)
        logger = get_logger()
        handler = logger.parent.handlers[0]
        record = logger.makeRecord(
            logger.name,
            logging.INFO,
            __file__,
            1,
            "hello",
            (),
            None,
        )
        payload = json.loads(handler.format(record))
        assert payload["level"] == "INFO"
        assert payload["logger"] == "asyncio_socks_server"
        assert payload["message"] == "hello"


class TestGetLogger:
    def test_returns_named_logger(self):
        logger = get_logger()
        assert logger.name == "asyncio_socks_server"


class TestFmtAddr:
    def test_ipv4(self):
        assert fmt_addr(Address("127.0.0.1", 1080)) == "127.0.0.1:1080"

    def test_ipv6(self):
        assert fmt_addr(Address("::1", 443)) == "::1:443"

    def test_domain(self):
        assert fmt_addr(Address("example.com", 80)) == "example.com:80"


class TestFmtConnection:
    def test_format(self):
        src = Address("10.0.0.1", 54321)
        dst = Address("93.184.216.34", 443)
        result = fmt_connection(src, dst)
        assert result == "10.0.0.1:54321 → 93.184.216.34:443"


class TestFmtBytes:
    def test_zero(self):
        assert fmt_bytes(0) == "0B"

    def test_bytes(self):
        assert fmt_bytes(512) == "512B"

    def test_boundary_1023(self):
        assert fmt_bytes(1023) == "1023B"

    def test_boundary_1024(self):
        assert fmt_bytes(1024) == "1.0KB"

    def test_kilobytes(self):
        assert fmt_bytes(2048) == "2.0KB"

    def test_just_under_mb(self):
        assert fmt_bytes(1024 * 1024 - 1) == "1024.0KB"

    def test_exact_mb(self):
        assert fmt_bytes(1024 * 1024) == "1.0MB"

    def test_megabytes(self):
        assert fmt_bytes(5 * 1024 * 1024) == "5.0MB"


class TestFmtEvent:
    def test_formats_machine_readable_event(self):
        assert (
            fmt_event(
                "flow_closed",
                flow_id=7,
                proto="tcp",
                src=Address("127.0.0.1", 1234),
                dst=Address("example.com", 443),
                bytes_up=10,
            )
            == "event=flow_closed flow_id=7 proto=tcp "
            "src=127.0.0.1:1234 dst=example.com:443 bytes_up=10"
        )

    def test_quotes_values_with_spaces(self):
        assert fmt_event("client_error", error="bad request") == (
            'event=client_error error="bad request"'
        )
