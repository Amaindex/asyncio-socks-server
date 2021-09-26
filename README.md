# asyncio-socks-server

![Latest version](https://img.shields.io/pypi/v/asyncio-socks-server?color=537CDE&label=Latest&logo=pypi&logoColor=white)
![Build](https://img.shields.io/github/workflow/status/Amaindex/asyncio-socks-server/Release?color=89E0A3&label=Build&logo=github&logoColor=white)
![Image](https://img.shields.io/github/workflow/status/Amaindex/asyncio-socks-server/Image?color=89E0A3&label=Image&logo=github&logoColor=white)
![Tests](https://img.shields.io/github/workflow/status/Amaindex/asyncio-socks-server/Tests?color=89E0A3&label=Tests&logo=github)
![Build](https://img.shields.io/docker/image-size/amaindex/asyncio-socks-server?color=F29CF2&logo=docker&logoColor=white&sort=semver)

A SOCKS proxy server implemented with the powerful python cooperative concurrency framework **asyncio**. 

## Features

- Supports both TCP and UDP with the implementation of SOCKS5 protocol
- Supports username/password authentication
- Provides optional strict mode that follows [RFC1928](https://www.ietf.org/rfc/rfc1928.txt) and [RFC1929](https://www.ietf.org/rfc/rfc1929.txt) without compromise
- Driven by the python standard library, no third-party dependencies

## Installation
Install with pip if Python version 3.8.0 or higher is available.
```shell
pip install asyncio-socks-server
```

Or pull a docker image from the [Docker Hub registry](https://hub.docker.com/r/amaindex/asyncio-socks-server).
```shell
docker pull amaindex/asyncio-socks-server
```

## Usage
When installed with pip, you can invoke asyncio-socks-server from the command-line:
```shell
asyncio_socks_server [-h] [-v] 
                     [-H HOST] [-P PORT] [-A METHOD] 
                     [--access-log] [--debug] [--strict] 
                     [--env-prefix ENV_PREFIX]
                     [--config PATH]
```
where:

- `asyncio_socks_server`: You could use python -m asyncio_socks_server in development.
- `-h`, `--help`: Show a help message and exit.
- `-v`, `--version`: Show program's version number and exit.
- `-H HOST`, `--host HOST`: Host address to listen (default 0.0.0.0).
- `-P PORT`, `--port PORT`: Port to listen (default 1080).
- `-A METHOD`, `--auth METHOD`: Authentication method (default 0). 
  Possible values: 0 (no auth), 2 (username/password auth)
- `--access-log`: Display access log.
- `--debug`: Work in debug mode.
- `--strict`: Work in strict compliance with RFC1928 and RFC1929.

If the value of `METHOD` is 2, that is, when the username/password authentication 
is specified, you need to provide a config file containing the usernames and passwords 
in json format with the `--config` option.
You can also list other options in the config file instead of the command：

`config.json`:
```json
{
  "LISTEN_HOST": "0.0.0.0",
  "LISTEN_PORT": 1080,
  "AUTH_METHOD": 2,
  "ACCESS_LOG": true,
  "DEBUG": true,
  "STRICT": true,
  "USERS": {
    "username1": "password1",
    "username2": "password2",
    "username3": "password3"
  }
}

```
```shell
asyncio_socks_server --config ${ENV}/config.json
```
In addition, any environment variable named starting with `AIOSS_` will also be applied 
to the option. 
The prefix can be changed by specifying the `--env-prefix` option，for example:
```shell
export MY_LISTEN_HOST=127.0.0.1
export MY_LISTEN_PORT=9999
asyncio_socks_server --env-prefix MY_
```

**NOTE:** The loading order of the options is: config file, environment variables, command options. 
The latter will overwrite the former if options are given in multiple ways.

Alternatively, if you use the docker image, you can launch the asyncio-socks-server with the following command:
```shell
docker run amaindex/asyncio-socks-server [-h] [-v] 
                                         [-H HOST] [-P PORT] [-A METHOD] 
                                         [--access-log] [--debug] [--strict] 
                                         [--env-prefix ENV_PREFIX]
                                         [--config PATH]
```
The network mode `host` is recommended since asyncio-socks-server uses multiple ports dynamically. 
If you also want to provide a config file, it should be mounted manually.
```shell
docker run \
    --rm \
    --net=host \
    -v /host/path/config.json:/config.json \ 
    amaindex/asyncio-socks-server \
    --config /config.json
```

## Strict Mode

For various reasons, asyncio-socks-server has made some compromises on the 
Implementation details of the protocols. Therefore, in the following scenes, 
asyncio-socks-server’s behavior will be divergent from that described in RFC1928 
and RFC1929.

### asyncio-socks-server relays all UDP datagrams by default

In the SOCKS5 negotiation, a UDP ASSOCIATE request formed as follows is used to 
establish an association within the UDP relay process to handle UDP datagrams:
```text
+----+-----+-------+------+----------+----------+
|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+
```
Normally, the DST.ADDR and DST.PORT fields contain the address and port that the 
client expects to use to send UDP datagrams on for the association, or use a port number 
and address of all zeros if the client does not possess this information. 
Therefore, when the client is working in a network that uses NAT, the DST.ADDR 
with all zeros should be used to avoid errors. But in case some clients 
did not follow this principle correctly, asyncio-socks-server relays all UDP datagrams 
it receives by default instead of using DST.ADDR and DST.PORT to limit the access.


### asyncio-socks-server allows "V5" username/password authentication

Once the client selects the username/password authentication during negotiation, 
it will conduct a sub-negotiation with the server. This sub-negotiation begins with 
the client producing a request:
```text
+----+------+----------+------+----------+
|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
+----+------+----------+------+----------+
| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
+----+------+----------+------+----------+
```
The VER field contains the current version of the sub-negotiation, which is X'01' but
often considered as X'05' since it's a bit counter-intuitive. 
So asyncio-socks-server allows requests with VER X'05' in non-strict mode.

### `--strict` option

To disable the compromise described above, you can specify the `--strict` option:
```shell
asyncio_socks_server --strict
```

## Reference

- [RFC1928](https://www.ietf.org/rfc/rfc1928.txt)
- [RFC1929](https://www.ietf.org/rfc/rfc1929.txt)
- [Anorov/PySocks](https://github.com/Anorov/PySocks)
- [Aber/socks5](https://github.com/Aber-s-practice/socks5)
- [Ehco1996/aioshadowsocks](https://github.com/Ehco1996/aioshadowsocks)
