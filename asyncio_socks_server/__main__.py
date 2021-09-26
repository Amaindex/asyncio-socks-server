import argparse
from argparse import RawTextHelpFormatter

from asyncio_socks_server.__version__ import __version__
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
        version=f"version {__version__}",
        help="Show program's version number and exit.\n ",
    )

    parser.add_argument(
        "-H",
        "--host",
        dest="host",
        type=str,
        default=None,
        help="Host address to listen (default 0.0.0.0).",
    )

    parser.add_argument(
        "-P",
        "--port",
        dest="port",
        type=int,
        default=None,
        help="Port to listen (default 1080).",
    )

    parser.add_argument(
        "-A",
        "--auth",
        dest="method",
        type=int,
        default=None,
        help=(
            "Authentication method (default 0).\n"
            "Possible values: "
            "0 (no auth), "
            "2 (username/password auth)\n "
        ),
    )

    parser.add_argument(
        "--access-log",
        dest="access_log",
        help="Display access log.",
        default=None,
        action="store_true",
    )

    parser.add_argument(
        "--debug",
        dest="debug",
        help="Work in debug mode.",
        default=None,
        action="store_true",
    )

    parser.add_argument(
        "--strict",
        dest="strict",
        help="Work in strict compliance with RFC1928 and RFC1929.\n ",
        default=None,
        action="store_true",
    )

    parser.add_argument(
        "--env-prefix",
        dest="env_prefix",
        type=str,
        default=SOCKS_SERVER_PREFIX,
        help=f"Prefix of the environment variable to be loaded as the config \n"
        f"(default is {SOCKS_SERVER_PREFIX}).",
    )

    parser.add_argument(
        "--config",
        dest="path",
        type=str,
        default=None,
        help="Path to the config file in json format.\n"
        "Example: ./${ENV}/config.json",
    )

    args = parser.parse_args()

    config_args = {
        "LISTEN_HOST": args.host,
        "LISTEN_PORT": args.port,
        "AUTH_METHOD": args.method,
        "ACCESS_LOG": args.access_log,
        "DEBUG": args.debug,
        "STRICT": args.strict,
    }

    app = SocksServer(
        config=args.path,
        env_prefix=args.env_prefix,
        **{k: v for k, v in config_args.items() if v is not None},
    )
    app.run()


if __name__ == "__main__":
    main()
