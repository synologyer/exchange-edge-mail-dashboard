FROM python:3.12-alpine
LABEL org.opencontainers.image.title="Exchange Edge Mail Dashboard" \
      org.opencontainers.image.description="Read-only web dashboard for Exchange 2019 Edge Transport logs"
WORKDIR /app
COPY app.py /app/app.py
COPY static /app/static
RUN pip install --no-cache-dir "paramiko==3.5.1" && \
    addgroup -S dashboard && adduser -S -G dashboard dashboard && \
    mkdir -p /tmp/edge-logs && chown -R dashboard:dashboard /tmp/edge-logs
USER dashboard
ENV LOG_ROOT=/logs PORT=8080 CACHE_SECONDS=60 MAX_ROWS=10000
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/api/health | grep -q '"status": "ok"' || exit 1
ENTRYPOINT ["python3", "/app/app.py"]
