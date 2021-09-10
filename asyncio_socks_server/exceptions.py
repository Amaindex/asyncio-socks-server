class ServerException(Exception):

    pass


class LoadFileError(ServerException):

    pass


class SocksException(Exception):

    pass


class NoVersionAllowed(SocksException):

    pass


class NoCommandAllowed(SocksException):

    pass


class CommandExecError(SocksException):

    pass


class HeaderParseError(SocksException):

    pass


class NoAtypAllowed(SocksException):

    pass


class AuthenticationError(SocksException):

    pass


class NoAuthMethodAllowed(SocksException):

    pass
