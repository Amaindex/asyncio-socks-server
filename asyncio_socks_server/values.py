from enum import IntEnum


class Socks5Rep(IntEnum):
    SUCCEEDED = 0
    GENERAL_SOCKS_SERVER_FAILURE = 1
    CONNECTION_NOT_ALLOWED_BY_RULESET = 2
    NETWORK_UNREACHABLE = 3
    HOST_UNREACHABLE = 4
    CONNECTION_REFUSED = 5
    TTL_EXPIRED = 6
    COMMAND_NOT_SUPPORTED = 7
    ADDRESS_TYPE_NOT_SUPPORTED = 8
    ADDRESS_NOT_ALLOWED = 9


class Socks4Rep(IntEnum):
    REQUEST_GRANTED = 90
    REQUEST_REJECTED_OR_FAILED = 91
    ADDRESS_NOT_ALLOWED = 92


class SocksAuthMethod(IntEnum):
    NO_AUTH = 0
    UP_AUTH = 2


class SocksCommand(IntEnum):
    CONNECT = 1
    BIND = 2
    UDP_ASSOCIATE = 3


class SocksAtyp(IntEnum):
    IPV4 = 1
    DOMAIN = 3
    IPV6 = 4
