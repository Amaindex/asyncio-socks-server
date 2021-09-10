import socket
import sys
import traceback

import socks

try:
    import socks

    socks.set_default_proxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 8848)
    socket.socket = socks.socksocket
except ImportError:
    sys.exit("You must install `socks` to run test.\nlike run `pip install pysocks`")

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    msg = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05\x62\x61\x69\x64\x75\x03\x63\x6f\x6d\x00\x00\x01\x00\x01"

    sock.sendto(
        msg,
        ("223.5.5.5", 53),
    )
    sock.settimeout(5)
    r = sock.recv(4096)
    print(msg)
    print(r)
    sock.close()
except socket.error:
    traceback.print_exc()
