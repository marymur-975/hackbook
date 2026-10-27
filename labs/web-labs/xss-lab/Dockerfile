# Уязвимое приложение XSS-лаборатории hackbook.
FROM python:3.12-alpine

LABEL org.opencontainers.image.title="hackbook xss-lab" \
      org.opencontainers.image.description="Намеренно уязвимое приложение для обучения XSS (reflected/stored/DOM-контексты)"

RUN addgroup -S lab && adduser -S -G lab lab \
    && mkdir -p /app /data && chown -R lab:lab /app /data

WORKDIR /app
COPY app.py /app/app.py

USER lab
ENV PORT=8080 \
    DB_PATH=/data/app.db \
    PYTHONUNBUFFERED=1

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2).status==200 else 1)"

CMD ["python", "app.py"]
