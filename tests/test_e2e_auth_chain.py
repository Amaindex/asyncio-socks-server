import pytest

from asyncio_socks_server import ChainRouter, connect
from asyncio_socks_server.core.types import Address
from tests.conftest import _start_server, _stop_server


class TestAuthChain:
    async def test_chain_with_auth_at_entry(self, echo_server):
        exit_server, exit_task = await _start_server()
        chain = ChainRouter(next_hop=f"127.0.0.1:{exit_server.port}")
        entry_server, entry_task = await _start_server(
            auth=("admin", "secret"),
            addons=[chain],
        )

        try:
            conn = await connect(
                Address(entry_server.host, entry_server.port),
                echo_server,
                username="admin",
                password="secret",
            )
            conn.writer.write(b"auth-chain")
            await conn.writer.drain()
            assert await conn.reader.read(4096) == b"auth-chain"
            conn.writer.close()
            await conn.writer.wait_closed()
        finally:
            await _stop_server(entry_server, entry_task)
            await _stop_server(exit_server, exit_task)

    async def test_chain_with_auth_at_exit(self, echo_server):
        exit_server, exit_task = await _start_server(auth=("u", "p"))
        chain = ChainRouter(
            next_hop=f"127.0.0.1:{exit_server.port}",
            username="u",
            password="p",
        )
        entry_server, entry_task = await _start_server(addons=[chain])

        try:
            conn = await connect(
                Address(entry_server.host, entry_server.port), echo_server
            )
            conn.writer.write(b"chain-auth-exit")
            await conn.writer.drain()
            assert await conn.reader.read(4096) == b"chain-auth-exit"
            conn.writer.close()
            await conn.writer.wait_closed()
        finally:
            await _stop_server(entry_server, entry_task)
            await _stop_server(exit_server, exit_task)

    async def test_chain_both_hops_require_auth(self, echo_server):
        exit_server, exit_task = await _start_server(auth=("exit_u", "exit_p"))
        chain = ChainRouter(
            next_hop=f"127.0.0.1:{exit_server.port}",
            username="exit_u",
            password="exit_p",
        )
        entry_server, entry_task = await _start_server(
            auth=("entry_u", "entry_p"),
            addons=[chain],
        )

        try:
            conn = await connect(
                Address(entry_server.host, entry_server.port),
                echo_server,
                username="entry_u",
                password="entry_p",
            )
            conn.writer.write(b"double-auth")
            await conn.writer.drain()
            assert await conn.reader.read(4096) == b"double-auth"
            conn.writer.close()
            await conn.writer.wait_closed()
        finally:
            await _stop_server(entry_server, entry_task)
            await _stop_server(exit_server, exit_task)

    async def test_chain_auth_failure_propagates(self, echo_server):
        from asyncio_socks_server.core.protocol import ProtocolError

        exit_server, exit_task = await _start_server()
        chain = ChainRouter(next_hop=f"127.0.0.1:{exit_server.port}")
        entry_server, entry_task = await _start_server(
            auth=("good", "creds"),
            addons=[chain],
        )

        try:
            with pytest.raises(ProtocolError, match="authentication failed"):
                await connect(
                    Address(entry_server.host, entry_server.port),
                    echo_server,
                    username="good",
                    password="wrong",
                )
        finally:
            await _stop_server(entry_server, entry_task)
            await _stop_server(exit_server, exit_task)
