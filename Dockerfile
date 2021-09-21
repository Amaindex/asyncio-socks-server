FROM python:3.8-slim-buster as base

LABEL Name="asyncio-socks-server" Author="Amaindex"

COPY ./asyncio_socks_server ./asyncio_socks_server

ENTRYPOINT ["python", "-m", "asyncio_socks_server"]
