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


class TestFileAuth:
    async def test_valid_credentials(self, tmp_path):
        cred_file = tmp_path / "creds.json"
        cred_file.write_text(json.dumps({"admin": "secret", "user": "pass"}))

        auth = FileAuth(cred_file)
        assert await auth.on_auth("admin", "secret") is True
        assert await auth.on_auth("admin", "wrong") is False

    async def test_unknown_user(self, tmp_path):
        cred_file = tmp_path / "creds.json"
        cred_file.write_text(json.dumps({"admin": "secret"}))

        auth = FileAuth(cred_file)
        assert await auth.on_auth("unknown", "any") is None

    async def test_missing_file(self, tmp_path):
        auth = FileAuth(tmp_path / "nonexistent.json")
        assert await auth.on_auth("any", "any") is None


class TestIPFilter:
    async def test_blocked(self):
        f = IPFilter(blocked=["10.0.0.0/8", "192.168.1.1"])
        # 172.16.0.1 is NOT blocked → returns None
        result = await f.on_connect(_make_flow(src=Address("172.16.0.1", 0)))
        assert result is None
        # 10.0.0.5 IS blocked → raises
        with pytest.raises(ConnectionRefusedError):
            await f.on_connect(_make_flow(src=Address("10.0.0.5", 0)))

    async def test_allowed_list(self):
        f = IPFilter(allowed=["127.0.0.0/8"])
        # 127.0.0.1 should be allowed (returns None)
        result = await f.on_connect(_make_flow())
        assert result is None

    async def test_not_in_allowed(self):
        f = IPFilter(allowed=["127.0.0.0/8"])
        with pytest.raises(ConnectionRefusedError):
            await f.on_connect(_make_flow(src=Address("10.0.0.1", 0)))

    async def test_no_rules(self):
        f = IPFilter()
        result = await f.on_connect(_make_flow(src=Address("10.0.0.1", 0)))
        assert result is None


class TestLogger:
    async def test_on_connect(self):
        logger = Logger()
        result = await logger.on_connect(
            _make_flow(src=Address("127.0.0.1", 1080), dst=Address("example.com", 80))
        )
        assert result is None

    async def test_on_data(self):
        logger = Logger()
        flow = _make_flow()
        result = await logger.on_data(Direction.UPSTREAM, b"hello", flow)
        assert result == b"hello"

    async def test_on_error(self):
        logger = Logger()
        await logger.on_error(ValueError("test"))
