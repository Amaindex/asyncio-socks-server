from __future__ import annotations

import argparse

from asyncio_socks_server.server.server import Server


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="asyncio_socks_server",
        description="A SOCKS5 proxy server with programmable addons",
    )
    parser.add_argument("--host", default="::", help="bind address")
    parser.add_argument("--port", type=int, default=1080, help="bind port")
    parser.add_argument(
        "--auth",
        default=None,
        help="username:password for authentication",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="logging level",
    )
    args = parser.parse_args()

    auth = None
    if args.auth:
        user, _, passwd = args.auth.partition(":")
        auth = (user, passwd)

    server = Server(
        host=args.host,
        port=args.port,
        auth=auth,
        log_level=args.log_level,
    )
    server.run()
