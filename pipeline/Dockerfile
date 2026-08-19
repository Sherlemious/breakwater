# syntax=docker/dockerfile:1.7
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.5.30 /uv /usr/local/bin/uv
RUN --mount=type=cache,target=/root/.cache/uv \
    uv venv /opt/venv && \
    uv pip install --python /opt/venv/bin/python \
      "numpy>=2.0.0" \
      "scapy>=2.5.0" \
      "scikit-learn>=1.4.0" \
      "joblib>=1.3.0"

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    PATH="/opt/venv/bin:${PATH}" \
    SQLITE_DB_PATH=/app/db/ddos_tool.db \
    MODEL_ARTIFACT_DIR=/app/data

WORKDIR /app

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update \
    && apt-get install -y --no-install-recommends bash libpcap0.8 tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv
COPY ingestion/ ./ingestion/
COPY model/ ./model/
COPY mitigation/ ./mitigation/
COPY pipeline/ ./pipeline/

RUN mkdir -p /app/data /app/db /app/input \
    && chmod +x /app/pipeline/run_pipeline.sh

VOLUME ["/app/data"]

ENTRYPOINT ["/app/pipeline/run_pipeline.sh"]
