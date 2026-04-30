FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN pip install --no-cache-dir --root-user-action=ignore . \
    && useradd --create-home --shell /usr/sbin/nologin appuser

USER appuser

EXPOSE 1080

ENTRYPOINT ["asyncio_socks_server"]
CMD ["--host", "0.0.0.0", "--port", "1080"]
