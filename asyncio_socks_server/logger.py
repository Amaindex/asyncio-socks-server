import logging
import sys

from asyncio_socks_server.config import Config


def gen_log_config(config: Config):
    server_log_level = "DEBUG" if config.DEBUG else "INFO"
    server_log_formatter = "diagnostic" if config.DEBUG else "generic"

    return {
        "version": 1,
        "disable_existing_loggers": False,
        "loggers": {
            "socks_server.root": {"level": server_log_level, "handlers": ["console"]},
            "socks_server.error": {
                "level": server_log_level,
                "handlers": ["error_console"],
                "propagate": True,
                "qualname": "socks_server.error",
            },
            "socks_server.access": {
                "level": server_log_level,
                "handlers": ["access_console"],
                "propagate": True,
                "qualname": "socks_server.access",
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": server_log_formatter,
                "stream": sys.stdout,
            },
            "error_console": {
                "class": "logging.StreamHandler",
                "formatter": server_log_formatter,
                "stream": sys.stderr,
            },
            "access_console": {
                "class": "logging.StreamHandler",
                "formatter": server_log_formatter,
                "stream": sys.stdout,
            },
        },
        "formatters": {
            "generic": {
                "format": "%(asctime)s | %(levelname)-8s | %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S %z",
                "class": "logging.Formatter",
            },
            "diagnostic": {
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d \n└─%(message)s\n",
                "datefmt": "%Y-%m-%d %H:%M:%S %z",
                "class": "logging.Formatter",
            },
        },
    }


logger = logging.getLogger("socks_server.root")

error_logger = logging.getLogger("socks_server.error")

access_logger = logging.getLogger("socks_server.access")
