from __future__ import annotations

import argparse

from asyncio_socks_server.core.logging import setup_logging
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
    parser.add_argument(
        "--log-format",
        default="text",
        choices=["text", "json"],
        help="logging format",
    )
    args = parser.parse_args()

    auth = None
    if args.auth:
        user, _, passwd = args.auth.partition(":")
        auth = (user, passwd)

    setup_logging(args.log_level, log_format=args.log_format, force=True)
    server = Server(
        host=args.host,
        port=args.port,
        auth=auth,
        log_level=args.log_level,
        log_format=args.log_format,
    )
    server.run()
