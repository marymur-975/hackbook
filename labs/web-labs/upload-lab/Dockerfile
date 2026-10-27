# Уязвимое приложение лаборатории загрузки файлов hackbook.
FROM python:3.12-alpine

LABEL org.opencontainers.image.title="hackbook upload-lab" \
      org.opencontainers.image.description="Намеренно уязвимая загрузка файлов: blacklist расширений, MIME из клиента, traversal в имени, stored XSS"

RUN addgroup -S lab && adduser -S -G lab lab \
    && mkdir -p /app /data/uploads && chown -R lab:lab /app /data

WORKDIR /app
COPY app.py /app/app.py

USER lab
ENV PORT=8080 \
    UPLOAD_DIR=/data/uploads \
    STATE_DB=/data/app.db \
    PYTHONUNBUFFERED=1

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2).status==200 else 1)"

CMD ["python", "app.py"]
