from __future__ import annotations

import ipaddress
import socket


def _is_ipv6(host: str) -> bool:
    try:
        ipaddress.IPv6Address(host)
        return True
    except ValueError:
        return False


def create_dualstack_tcp_socket(host: str, port: int) -> socket.socket:
    """Create a TCP server socket with dual-stack (IPv4+IPv6) support."""
    if host in ("", "::"):
        return socket.create_server(
            ("::", port), family=socket.AF_INET6, dualstack_ipv6=True
        )
    if host == "0.0.0.0":
        return socket.create_server((host, port), family=socket.AF_INET)
    if _is_ipv6(host):
        return socket.create_server((host, port), family=socket.AF_INET6)
    return socket.create_server((host, port))


def create_dualstack_udp_socket(host: str, port: int = 0) -> socket.socket:
    """Create a UDP socket with dual-stack support."""
    if host in ("0.0.0.0", "", "::"):
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        sock.bind(("::", port))
    elif _is_ipv6(host):
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.bind((host, port))
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((host, port))
    return sock
