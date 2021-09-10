from asyncio_socks_server.app import SocksServer
from asyncio_socks_server.logger import logger

if __name__ == "__main__":
    app = SocksServer()
    app.run()
