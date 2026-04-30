"""Tests for core logging module."""

import logging

from asyncio_socks_server.core.logging import (
    fmt_addr,
    fmt_bytes,
    fmt_connection,
    get_logger,
    setup_logging,
)
from asyncio_socks_server.core.types import Address


class TestSetupLogging:
    def test_sets_level_debug(self):
        setup_logging("DEBUG")
        logger = get_logger()
        assert logger.parent.level == logging.DEBUG

    def test_sets_level_info(self):
        setup_logging("INFO")
        logger = get_logger()
        assert logger.parent.level == logging.INFO


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
