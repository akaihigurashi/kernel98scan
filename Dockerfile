# kernel98scan - Check whether a Linux host is exposed to CVE-2026-98432 (kernel IPv4 TCP use-after-free)
FROM python:3.13-slim

LABEL org.opencontainers.image.title="kernel98scan" \
      org.opencontainers.image.description="Check whether a Linux host is exposed to CVE-2026-98432 (kernel IPv4 TCP use-after-free)" \
      org.opencontainers.image.licenses="GPL-3.0-only"

# unprivileged user, writable data volume (blocklist cache + audit log)
RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin scanner \
 && mkdir -p /data && chown 10001:10001 /data

WORKDIR /app
COPY kernel98scan.py web.py ./
COPY static ./static

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PANIC_BIND=0.0.0.0 \
    PANIC_PORT=8092 \
    STATE_DIRECTORY=/data \
    PANIC_AUDIT_DIR=/data/audit \
    PANIC_RETENTION_DAYS=30

USER 10001
VOLUME ["/data"]
EXPOSE 8092

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8092/healthz', timeout=3)" || exit 1

ENTRYPOINT ["python3", "web.py"]
