FROM python:3.12-slim

# uv for fast, lockfile-exact installs
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    AUTH_DEMO_DB=/data/demo.db

# Install dependencies first so this layer is cached until the lockfile changes
COPY pyproject.toml uv.lock .python-version ./
RUN uv sync --frozen --no-install-project

# Then copy the application code
COPY api ./api
COPY web ./web
COPY scripts ./scripts
COPY tests ./tests
COPY schema.sql README.md ./

RUN mkdir -p /data

EXPOSE 8000

# 0.0.0.0 so the published port is reachable from the host
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
