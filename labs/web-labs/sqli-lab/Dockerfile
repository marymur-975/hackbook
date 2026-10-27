# Уязвимое приложение SQLi-лаборатории hackbook.
# Только stdlib Python — никаких pip-зависимостей, сборка работает офлайн.
FROM python:3.12-alpine

LABEL org.opencontainers.image.title="hackbook sqli-lab" \
      org.opencontainers.image.description="Намеренно уязвимое приложение для обучения SQL Injection" \
      org.opencontainers.image.source="https://github.com/hackbook/hackbook"

# не root: даже в уязвимом приложении соблюдаем базовую гигиену
RUN addgroup -S lab && adduser -S -G lab lab \
    && mkdir -p /app /data && chown -R lab:lab /app /data

WORKDIR /app
COPY app.py /app/app.py

USER lab
ENV PORT=8080 \
    DB_PATH=/data/app.db \
    SHOW_DB_ERRORS=1 \
    PYTHONUNBUFFERED=1

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2).status==200 else 1)"

# read-only rootfs задаётся в docker-compose, /data остаётся перезаписываемым томом
CMD ["python", "app.py"]
