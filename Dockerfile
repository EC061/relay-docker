FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    autossh \
    openssh-client \
    iproute2 \
    procps \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates/ templates/
COPY static/ static/
COPY defaults/ defaults/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV DATA_DIR=/data \
    GUI_USER=admin \
    GUI_PASS=changeme \
    PORT=8080

EXPOSE 8080
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://127.0.0.1:${PORT:-8080}/healthz || exit 1

ENTRYPOINT ["/entrypoint.sh"]
