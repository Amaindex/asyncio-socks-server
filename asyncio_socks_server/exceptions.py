class ServerException(Exception):
    """Base exception of socks server."""


class LoadFileError(ServerException):
    """Socks server failed to load file."""


class SocksException(Exception):
    """Base exception of socks protocol."""


class NoVersionAllowed(SocksException):
    """The server does not support the socks protocol version used by the client."""


class NoCommandAllowed(SocksException):
    """The server does not support the socks command from the client."""


class CommandExecError(SocksException):
    """An error occurred during the execution of the socks command."""


class HeaderParseError(SocksException):
    """An error occurred during parsing of the socks header"""


class NoAtypAllowed(SocksException):
    """The server does not support the address type specified in the request."""


class AuthenticationError(SocksException):
    """Failed to authenticate the client."""


class NoAuthMethodAllowed(SocksException):
    """The server does not support the authentication methods provided by the client."""
