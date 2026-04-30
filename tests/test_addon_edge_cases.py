"""Addon dispatch edge cases: competitive, pipeline, exceptions."""

from asyncio_socks_server.addons.base import Addon
from asyncio_socks_server.addons.manager import AddonManager
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


class ConnectReturning(Addon):
    def __init__(self, value=None):
        self._value = value

    async def on_connect(self, flow):
        return self._value


class TrackingAddon(Addon):
    def __init__(self, name, calls):
        self._name = name
        self._calls = calls

    async def on_start(self):
        self._calls.append(f"{self._name}:on_start")

    async def on_stop(self):
        self._calls.append(f"{self._name}:on_stop")


class DataTransform(Addon):
    def __init__(self, transform_fn):
        self._fn = transform_fn

    async def on_data(self, direction, data, flow):
        return self._fn(data)


class ErrorRaiser(Addon):
    def __init__(self, raise_on_error=False):
        self._raise_on_error = raise_on_error
        self.errors = []

    async def on_error(self, error):
        self.errors.append(error)
        if self._raise_on_error:
            raise RuntimeError("addon error")


class AuthAddon(Addon):
    def __init__(self, result):
        self._result = result

    async def on_auth(self, username, password):
        return self._result


class TestCompetitiveConnect:
    async def test_first_addon_returns_connection(self):
        # Use a simple object as Connection proxy
        sentinel = object()
        a1 = ConnectReturning(value=sentinel)
        a2 = ConnectReturning(value=None)
        manager = AddonManager([a1, a2])
        result = await manager.dispatch_connect(
            _make_flow(src=Address("1.2.3.4", 0), dst=Address("5.6.7.8", 80))
        )
        assert result is sentinel

    async def test_second_addon_returns_connection(self):
        sentinel = object()
        a1 = ConnectReturning(value=None)
        a2 = ConnectReturning(value=sentinel)
        manager = AddonManager([a1, a2])
        result = await manager.dispatch_connect(
            _make_flow(src=Address("1.2.3.4", 0), dst=Address("5.6.7.8", 80))
        )
        assert result is sentinel

    async def test_no_addon_returns_connection(self):
        a1 = ConnectReturning(value=None)
        a2 = ConnectReturning(value=None)
        manager = AddonManager([a1, a2])
        result = await manager.dispatch_connect(
            _make_flow(src=Address("1.2.3.4", 0), dst=Address("5.6.7.8", 80))
        )
        assert result is None


class TestPipelineEdgeCases:
    async def test_pipeline_with_intermediate_none(self):
        call_log = []

        class LogAddon(Addon):
            def __init__(self, name, ret):
                self._name = name
                self._ret = ret

            async def on_data(self, direction, data, flow):
                call_log.append(self._name)
                return self._ret

        # First transforms, second returns None (drops), third should NOT be called
        manager = AddonManager(
            [
                LogAddon("upper", b"HELLO"),
                LogAddon("drop", None),
                LogAddon("lower", b"hello"),
            ]
        )
        result = await manager.dispatch_data(Direction.UPSTREAM, b"hello", _make_flow())
        assert result is None
        assert call_log == ["upper", "drop"]

    async def test_pipeline_empty_bytes(self):
        received = []

        class Capture(Addon):
            async def on_data(self, direction, data, flow):
                received.append(data)
                return data

        manager = AddonManager([Capture()])
        result = await manager.dispatch_data(Direction.UPSTREAM, b"", _make_flow())
        assert result == b""
        assert received == [b""]


class TestAddonExceptions:
    async def test_auth_addon_raises_exception(self):
        class FailAuth(Addon):
            async def on_auth(self, username, password):
                raise PermissionError("blocked")

        manager = AddonManager([FailAuth()])
        try:
            await manager.dispatch_auth("user", "pass")
            assert False, "Should have raised"
        except PermissionError:
            pass

    async def test_data_addon_raises_exception(self):
        class FailData(Addon):
            async def on_data(self, direction, data, flow):
                raise ValueError("bad data")

        manager = AddonManager([FailData()])
        try:
            await manager.dispatch_data(Direction.UPSTREAM, b"test", _make_flow())
            assert False, "Should have raised"
        except ValueError:
            pass

    async def test_error_addon_exception_suppressed(self):
        a1 = ErrorRaiser(raise_on_error=True)
        a2 = ErrorRaiser()
        manager = AddonManager([a1, a2])
        # Should not raise even though a1 raises in on_error
        await manager.dispatch_error(RuntimeError("test"))
        # a2 should still have been called
        assert len(a2.errors) == 1

    async def test_error_addon_all_called(self):
        a1 = ErrorRaiser()
        a2 = ErrorRaiser()
        a3 = ErrorRaiser()
        manager = AddonManager([a1, a2, a3])
        err = RuntimeError("test")
        await manager.dispatch_error(err)
        assert len(a1.errors) == 1
        assert len(a2.errors) == 1
        assert len(a3.errors) == 1


class TestLifecycleOrder:
    async def test_multiple_addons_start_stop_order(self):
        calls = []
        a1 = TrackingAddon("a1", calls)
        a2 = TrackingAddon("a2", calls)
        a3 = TrackingAddon("a3", calls)
        manager = AddonManager([a1, a2, a3])

        await manager.dispatch_start()
        assert calls == ["a1:on_start", "a2:on_start", "a3:on_start"]

        calls.clear()
        await manager.dispatch_stop()
        assert calls == ["a1:on_stop", "a2:on_stop", "a3:on_stop"]

    async def test_addon_with_only_data_override(self):
        class DataOnly(Addon):
            async def on_data(self, direction, data, flow):
                return data

        manager = AddonManager([DataOnly()])
        # auth should return None (not overridden)
        result = await manager.dispatch_auth("user", "pass")
        assert result is None
        # connect should return None
        result = await manager.dispatch_connect(
            _make_flow(src=Address("a", 1), dst=Address("b", 2))
        )
        assert result is None
        # data should pass through
        result = await manager.dispatch_data(Direction.UPSTREAM, b"test", _make_flow())
        assert result == b"test"


class TestCompetitiveAuth:
    async def test_first_auth_wins_true(self):
        manager = AddonManager([AuthAddon(True), AuthAddon(False)])
        result = await manager.dispatch_auth("user", "pass")
        assert result is True

    async def test_first_auth_wins_false(self):
        manager = AddonManager([AuthAddon(False), AuthAddon(True)])
        result = await manager.dispatch_auth("user", "pass")
        assert result is False

    async def test_all_none_passes_through(self):
        manager = AddonManager([AuthAddon(None), AuthAddon(None)])
        result = await manager.dispatch_auth("user", "pass")
        assert result is None
