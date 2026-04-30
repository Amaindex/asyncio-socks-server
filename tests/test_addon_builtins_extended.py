"""Extended tests for built-in addons: FileAuth, IPFilter, Logger."""

import json

import pytest

from asyncio_socks_server.addons.auth import FileAuth
from asyncio_socks_server.addons.ip_filter import IPFilter
from asyncio_socks_server.addons.logger import Logger
from asyncio_socks_server.core.types import Address, Direction, Flow


def _make_flow(**kwargs):
    defaults = dict(
        id=1,
        src=Address("127.0.0.1", 0),
        dst=Address("0.0.0.0", 0),
        protocol="tcp",
        started_at=0.0,
    )
    defaults.update(kwargs)
    return Flow(**defaults)


class TestFileAuthExtended:
    async def test_corrupted_json_file(self, tmp_path):
        bad_file = tmp_path / "auth.json"
        bad_file.write_text("not json at all {{{")
        auth = FileAuth(str(bad_file))
        result = await auth.on_auth("user", "pass")
        assert result is None

    async def test_empty_json_file(self, tmp_path):
        empty_file = tmp_path / "auth.json"
        empty_file.write_text("{}")
        auth = FileAuth(str(empty_file))
        result = await auth.on_auth("user", "pass")
        assert result is None

    async def test_credentials_cached_after_first_load(self, tmp_path):
        auth_file = tmp_path / "auth.json"
        auth_file.write_text(json.dumps({"user": "pass"}))
        auth = FileAuth(str(auth_file))

        # First load
        result = await auth.on_auth("user", "pass")
        assert result is True

        # Modify file
        auth_file.write_text("{}")

        # Should still use cached credentials
        result = await auth.on_auth("user", "pass")
        assert result is True

    async def test_unicode_credentials(self, tmp_path):
        auth_file = tmp_path / "auth.json"
        auth_file.write_text(json.dumps({"用户": "密码"}))
        auth = FileAuth(str(auth_file))
        result = await auth.on_auth("用户", "密码")
        assert result is True

    async def test_unknown_user(self, tmp_path):
        auth_file = tmp_path / "auth.json"
        auth_file.write_text(json.dumps({"admin": "secret"}))
        auth = FileAuth(str(auth_file))
        result = await auth.on_auth("unknown", "pass")
        assert result is None


class TestIPFilterExtended:
    async def test_ipv6_blocked(self):
        filt = IPFilter(blocked=["::1/128"])
        with pytest.raises(ConnectionRefusedError, match="IP blocked"):
            await filt.on_connect(
                _make_flow(src=Address("::1", 1234), dst=Address("1.2.3.4", 80))
            )

    async def test_ipv6_allowed(self):
        filt = IPFilter(allowed=["::1/128", "127.0.0.1/32"])
        # 127.0.0.1 should be allowed (returns None)
        result = await filt.on_connect(
            _make_flow(src=Address("127.0.0.1", 1234), dst=Address("1.2.3.4", 80))
        )
        assert result is None

    async def test_domain_source_falls_back(self):
        filt = IPFilter(blocked=["10.0.0.0/8"])
        # Domain source host — ip_address will raise ValueError
        try:
            await filt.on_connect(
                _make_flow(src=Address("example.com", 1234), dst=Address("1.2.3.4", 80))
            )
        except (ValueError, ConnectionRefusedError):
            pass  # Either is acceptable

    async def test_empty_rules(self):
        filt = IPFilter()
        # No rules → nothing blocked, should return None
        result = await filt.on_connect(
            _make_flow(src=Address("10.0.0.1", 1234), dst=Address("1.2.3.4", 80))
        )
        assert result is None


class TestLoggerExtended:
    async def test_on_data_returns_data_passthrough(self):
        logger = Logger()
        flow = _make_flow()
        result = await logger.on_data(Direction.UPSTREAM, b"test", flow)
        assert result == b"test"

    async def test_on_connect_returns_none(self):
        logger = Logger()
        result = await logger.on_connect(
            _make_flow(src=Address("1.2.3.4", 1234), dst=Address("5.6.7.8", 80))
        )
        assert result is None

    async def test_on_error_does_not_raise(self):
        logger = Logger()
        await logger.on_error(RuntimeError("test"))
        await logger.on_error(ConnectionError("test"))
        await logger.on_error(ValueError("test"))
