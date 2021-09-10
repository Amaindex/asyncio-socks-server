import socket
import traceback

import socks

s = socks.socksocket()  # Same API as socket.socket in the standard lib
s.set_proxy(socks.SOCKS5, "127.0.0.1", 8848, username="lizi", password="123456")

try:
    s.connect(("www.baidu.com", 80))

    s.sendall(b"GET / HTTP/1.1\r\n\r\n")
    print(s.recv(4096).decode())
except socket.error:
    traceback.print_exc()
