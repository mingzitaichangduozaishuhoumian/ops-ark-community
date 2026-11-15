FROM ghcr.io/astral-sh/uv:0.9.17 AS uv
FROM python:3.13-slim

COPY --from=uv /uv /usr/local/bin/uv
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_LINK_MODE=copy
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev \
    && useradd --create-home --uid 10001 opsark \
    && mkdir -p /app/data \
    && chown opsark:opsark /app/data \
    && chmod 700 /app/data
COPY src/ ./src/
COPY web/ ./web/
# Administrator staging directories may be 0700; only application assets need public read/traversal.
RUN chmod -R a+rX /app/src /app/web
ENV OPSARK_DATA_DIR=/app/data
USER opsark
EXPOSE 8010
CMD ["/app/.venv/bin/uvicorn", "opsark.main:app", "--app-dir", "src", "--host", "0.0.0.0", "--port", "8010", "--workers", "1"]
