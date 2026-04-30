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


class LifeCycleAddon(Addon):
    def __init__(self):
        self.started = False
        self.stopped = False

    async def on_start(self):
        self.started = True

    async def on_stop(self):
        self.stopped = True


class TestLifecycle:
    async def test_start_stop(self):
        addon = LifeCycleAddon()
        mgr = AddonManager([addon])
        await mgr.dispatch_start()
        assert addon.started
        await mgr.dispatch_stop()
        assert addon.stopped

    async def test_empty_manager(self):
        mgr = AddonManager([])
        await mgr.dispatch_start()
        await mgr.dispatch_stop()

    async def test_base_addon_skipped(self):
        mgr = AddonManager([Addon()])
        await mgr.dispatch_start()  # should not raise


class AuthAllow(Addon):
    async def on_auth(self, username, password):
        return True


class AuthDeny(Addon):
    async def on_auth(self, username, password):
        return False


class AuthPass(Addon):
    async def on_auth(self, username, password):
        return None


class TestCompetitiveAuth:
    async def test_first_allow_wins(self):
        mgr = AddonManager([AuthAllow(), AuthDeny()])
        result = await mgr.dispatch_auth("user", "pass")
        assert result is True

    async def test_first_deny_wins(self):
        mgr = AddonManager([AuthDeny(), AuthAllow()])
        result = await mgr.dispatch_auth("user", "pass")
        assert result is False

    async def test_all_pass(self):
        mgr = AddonManager([AuthPass(), AuthPass()])
        result = await mgr.dispatch_auth("user", "pass")
        assert result is None

    async def test_passthrough_then_allow(self):
        mgr = AddonManager([AuthPass(), AuthAllow()])
        result = await mgr.dispatch_auth("user", "pass")
        assert result is True


class UpperAddon(Addon):
    async def on_data(self, direction, data, flow):
        return data.upper()


class AppendAddon(Addon):
    async def on_data(self, direction, data, flow):
        return data + b"!"


class DropAddon(Addon):
    async def on_data(self, direction, data, flow):
        return None


class TestPipelineData:
    async def test_single_transform(self):
        mgr = AddonManager([UpperAddon()])
        result = await mgr.dispatch_data(Direction.UPSTREAM, b"hello", _make_flow())
        assert result == b"HELLO"

    async def test_chain_transforms(self):
        mgr = AddonManager([UpperAddon(), AppendAddon()])
        result = await mgr.dispatch_data(Direction.UPSTREAM, b"hello", _make_flow())
        assert result == b"HELLO!"

    async def test_drop_stops_pipeline(self):
        mgr = AddonManager([DropAddon(), UpperAddon()])
        result = await mgr.dispatch_data(Direction.UPSTREAM, b"hello", _make_flow())
        assert result is None

    async def test_no_addons(self):
        mgr = AddonManager([])
        result = await mgr.dispatch_data(Direction.UPSTREAM, b"hello", _make_flow())
        assert result == b"hello"


class ErrorAddon(Addon):
    def __init__(self):
        self.errors: list[Exception] = []

    async def on_error(self, error):
        self.errors.append(error)


class ErrorRaisingAddon(Addon):
    async def on_error(self, error):
        raise RuntimeError("observer crashed")


class TestObservationalError:
    async def test_all_called(self):
        a1 = ErrorAddon()
        a2 = ErrorAddon()
        mgr = AddonManager([a1, a2])
        err = ValueError("test")
        await mgr.dispatch_error(err)
        assert len(a1.errors) == 1
        assert len(a2.errors) == 1

    async def test_exception_doesnt_propagate(self):
        a1 = ErrorRaisingAddon()
        a2 = ErrorAddon()
        mgr = AddonManager([a1, a2])
        await mgr.dispatch_error(ValueError("test"))
        assert len(a2.errors) == 1  # second addon still called
