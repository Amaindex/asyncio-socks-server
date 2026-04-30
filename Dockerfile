FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN pip install --no-cache-dir --root-user-action=ignore . \
    && useradd --create-home --shell /usr/sbin/nologin appuser

USER appuser

EXPOSE 1080

ENTRYPOINT ["asyncio_socks_server"]
CMD ["--host", "::", "--port", "1080"]
