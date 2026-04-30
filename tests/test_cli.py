"""Tests for CLI argument parsing."""

from unittest.mock import MagicMock, patch

import pytest

from asyncio_socks_server.cli import main


class TestCliArgs:
    @patch("asyncio_socks_server.cli.Server")
    def test_default_values(self, mock_server_cls):
        with pytest.raises(SystemExit):
            # argparse exits on --help
            with patch("sys.argv", ["asyncio_socks_server", "--help"]):
                main()

    @patch("asyncio_socks_server.cli.Server")
    def test_custom_host_port(self, mock_server_cls):
        mock_instance = MagicMock()
        mock_server_cls.return_value = mock_instance
        with patch(
            "sys.argv",
            ["asyncio_socks_server", "--host", "127.0.0.1", "--port", "9050"],
        ):
            main()
        mock_server_cls.assert_called_once_with(
            host="127.0.0.1", port=9050, auth=None, log_level="INFO"
        )
        mock_instance.run.assert_called_once()

    @patch("asyncio_socks_server.cli.Server")
    def test_auth_parsing(self, mock_server_cls):
        mock_instance = MagicMock()
        mock_server_cls.return_value = mock_instance
        with patch("sys.argv", ["asyncio_socks_server", "--auth", "user:pass"]):
            main()
        mock_server_cls.assert_called_once_with(
            host="::", port=1080, auth=("user", "pass"), log_level="INFO"
        )

    @patch("asyncio_socks_server.cli.Server")
    def test_auth_with_colon_in_password(self, mock_server_cls):
        mock_instance = MagicMock()
        mock_server_cls.return_value = mock_instance
        with patch("sys.argv", ["asyncio_socks_server", "--auth", "user:pass:word"]):
            main()
        mock_server_cls.assert_called_once_with(
            host="::", port=1080, auth=("user", "pass:word"), log_level="INFO"
        )

    def test_invalid_log_level(self):
        with pytest.raises(SystemExit):
            with patch("sys.argv", ["asyncio_socks_server", "--log-level", "INVALID"]):
                main()

    @patch("asyncio_socks_server.cli.Server")
    def test_debug_log_level(self, mock_server_cls):
        mock_instance = MagicMock()
        mock_server_cls.return_value = mock_instance
        with patch("sys.argv", ["asyncio_socks_server", "--log-level", "DEBUG"]):
            main()
        mock_server_cls.assert_called_once_with(
            host="::", port=1080, auth=None, log_level="DEBUG"
        )

    @patch("asyncio_socks_server.cli.Server")
    def test_no_auth_flag(self, mock_server_cls):
        mock_instance = MagicMock()
        mock_server_cls.return_value = mock_instance
        with patch("sys.argv", ["asyncio_socks_server"]):
            main()
        call_kwargs = mock_server_cls.call_args[1]
        assert call_kwargs["auth"] is None
