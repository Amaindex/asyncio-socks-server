from os import environ
from pathlib import Path

import pytest

from asyncio_socks_server.exceptions import LoadFileError
from asyncio_socks_server.utils import (
    get_socks_atyp_from_host,
    load_dict_from_json_file_location,
)
from asyncio_socks_server.values import SocksAtyp


@pytest.mark.parametrize(
    "host,atyp",
    [
        ("127.0.0.1", SocksAtyp.IPV4),
        ("1080:0:0:0:8:800:200C:417A", SocksAtyp.IPV6),
        ("1080::8:800:200C:417A", SocksAtyp.IPV6),
        ("FF01:0:0:0:0:0:0:101", SocksAtyp.IPV6),
        ("FF01::101", SocksAtyp.IPV6),
        ("0:0:0:0:0:0:0:1", SocksAtyp.IPV6),
        ("::1", SocksAtyp.IPV6),
        ("0:0:0:0:0:0:0:0", SocksAtyp.IPV6),
        ("::", SocksAtyp.IPV6),
        ("www.example.com", SocksAtyp.DOMAIN),
        ("???", SocksAtyp.DOMAIN),
    ],
)
def test_get_socks_atyp_from_host(host, atyp):
    assert get_socks_atyp_from_host(host) == atyp


def test_load_dict_from_json_file_location_with_non_existing_file():
    with pytest.raises(FileNotFoundError):
        load_dict_from_json_file_location(
            str(Path(__file__).parent / "static" / "non_existing_config.json")
        )


def test_load_dict_from_json_file_location():
    dict_obj = load_dict_from_json_file_location(
        str(Path(__file__).parent / "static" / "config.json")
    )
    assert isinstance(dict_obj, dict)


def test_load_dict_from_json_file_location_with_non_existing_env_var():
    with pytest.raises(LoadFileError):
        load_dict_from_json_file_location(
            str(
                Path(__file__).parent / "static" / "${non_existing_var}" / "config.json"
            )
        )


def test_load_dict_from_json_file_location_with_env():
    environ["APP_TEST_CONFIG"] = str(Path(__file__).parent / "static" / "config.json")
    dict_obj = load_dict_from_json_file_location("${APP_TEST_CONFIG}")
    assert isinstance(dict_obj, dict)
