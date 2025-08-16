FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    APP_HOME=/app

WORKDIR ${APP_HOME}

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl ca-certificates tini && \
    rm -rf /var/lib/apt/lists/*

# Copy only requirement files first for better layer caching
COPY requirements-server.txt ./

RUN pip install --upgrade pip && \
    pip install -r requirements-server.txt

# Copy app
COPY atous_sec_network ./atous_sec_network
COPY start_server.py ./

# Non-root user
RUN useradd -ms /bin/bash appuser && \
    mkdir -p logs && chown -R appuser:appuser ${APP_HOME}
USER appuser

EXPOSE 8000

ENV HOST=0.0.0.0 \
    PORT=8000 \
    LOG_LEVEL=info

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["gunicorn", "-k", "uvicorn.workers.UvicornWorker", "-w", "4", "atous_sec_network.api.server:app", "--bind", "0.0.0.0:8000", "--timeout", "60"]

