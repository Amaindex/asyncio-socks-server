import argparse
from argparse import RawTextHelpFormatter

from asyncio_socks_server.app import SocksServer
from asyncio_socks_server.config import BASE_LOGO, SOCKS_SERVER_PREFIX, Config
from asyncio_socks_server.logger import logger


class AIOSSArgumentParser(RawTextHelpFormatter):
    def __init__(self, prog):
        super().__init__(prog, max_help_position=60)


def main():
    parser = argparse.ArgumentParser(
        prog="asyncio_socks_server",
        description=BASE_LOGO,
        formatter_class=AIOSSArgumentParser,
        add_help=False,
    )

    parser.add_argument(
        "-h",
        "--help",
        action="help",
        help="Show this help message and exit.",
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"version 1.0.0.1",
        help="Show program's version number and exit.\n ",
    )

    parser.add_argument(
        "-H",
        "--host",
        dest="host",
        type=str,
        default="0.0.0.0",
        help="Host address to listen (default 0.0.0.0).",
    )

    parser.add_argument(
        "-P",
        "--port",
        dest="port",
        type=int,
        default=1080,
        help="Port to listen (default 1080).",
    )

    parser.add_argument(
        "-A",
        "--auth",
        dest="method",
        type=int,
        default=0,
        help=(
            "Authentication method (default 0).\n"
            "Possible values: "
            "0 (no auth), "
            "2 (username/password auth)\n "
        ),
    )

    parser.add_argument(
        "--access-logs",
        dest="access_log",
        help="Display access logs.",
        action="store_true",
    )

    parser.add_argument(
        "--debug", dest="debug", help="Work in debug mode.", action="store_true"
    )

    parser.add_argument(
        "--strict",
        dest="strict",
        help="Work in strict compliance with RFC1928 and RFC1929.",
        action="store_true",
    )

    parser.add_argument(
        "--bind-addr",
        dest="bind_addr",
        type=str,
        default="0.0.0.0",
        help="Value of BIND.ADDR field in the reply (default 0.0.0.0).\n"
        "It is not necessary for most clients.\n ",
    )

    parser.add_argument(
        "--config",
        dest="path",
        type=str,
        default=None,
        help="Path to the config file in json format.\n" "Example: ./config.json",
    )

    parser.add_argument(
        "--env-prefix",
        dest="env_prefix",
        type=str,
        default=SOCKS_SERVER_PREFIX,
        help=f"Prefix of the environment variable to be loaded as the config \n"
        f"(default is {SOCKS_SERVER_PREFIX}).",
    )

    args = parser.parse_args()

    config_args = {
        "LISTEN_HOST": args.host,
        "LISTEN_PORT": args.port,
        "AUTH_METHOD": args.method,
        "ACCESS_LOG": args.access_log,
        "STRICT": args.strict,
        "BIND_ADDR": args.bind_addr,
        "DEBUG": args.debug,
    }

    app = SocksServer(config=args.path, env_prefix=args.env_prefix, **config_args)
    app.run()


if __name__ == "__main__":
    main()
