import socket

from asyncio_socks_server.core.socket import (
    create_dualstack_tcp_socket,
    create_dualstack_udp_socket,
)


def test_tcp_unspecified_ipv4_uses_ipv4_socket():
    sock = create_dualstack_tcp_socket("0.0.0.0", 0)
    try:
        assert sock.family == socket.AF_INET
    finally:
        sock.close()


def test_udp_unspecified_ipv4_uses_ipv4_socket():
    sock = create_dualstack_udp_socket("0.0.0.0", 0)
    try:
        assert sock.family == socket.AF_INET6
        assert sock.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY) == 0
    finally:
        sock.close()


def test_tcp_unspecified_ipv6_keeps_dualstack_socket():
    sock = create_dualstack_tcp_socket("::", 0)
    try:
        assert sock.family == socket.AF_INET6
        assert sock.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY) == 0
    finally:
        sock.close()
