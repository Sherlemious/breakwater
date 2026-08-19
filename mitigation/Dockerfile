# syntax=docker/dockerfile:1.7
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY mitigation/pyproject.toml ./pyproject.toml
COPY --from=ghcr.io/astral-sh/uv:0.5.30 /uv /usr/local/bin/uv
RUN --mount=type=cache,target=/root/.cache/uv \
    uv venv /opt/venv

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    PATH="/opt/venv/bin:${PATH}"

WORKDIR /app

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iptables \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv
COPY --from=ghcr.io/astral-sh/uv:0.5.30 /uv /usr/local/bin/uv

COPY mitigation/ ./mitigation/

RUN mkdir -p /app/data

VOLUME ["/app/data"]

CMD ["python", "-m", "mitigation", "--events-file", "/app/data/mitigation_events.json"]
