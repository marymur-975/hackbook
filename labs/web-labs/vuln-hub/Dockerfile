# vuln-hub: девять классов уязвимостей в одном стенде (stdlib Python).
FROM python:3.12-alpine

LABEL org.opencontainers.image.title="hackbook vuln-hub" \
      org.opencontainers.image.description="Учебный стенд: SQLi, IDOR, XSS, SSRF, XXE, CMDi, LFI, JWT, 2FA + безопасные аналоги каждого"

RUN addgroup -S lab && adduser -S -G lab lab \
    && mkdir -p /app /data /app/docs \
    && chown -R lab:lab /app /data \
    # iputils нужен для /ping (легитимная часть задания по command injection)
    && apk add --no-cache iputils

WORKDIR /app
COPY app.py selftest.py /app/
COPY docs/ /app/docs/

USER lab
ENV PORT=8080 \
    DB_PATH=/data/app.db \
    DOCS_DIR=/app/docs \
    JWT_SECRET=secret \
    ALLOWED_SSRF_HOSTS=example.com \
    PYTHONUNBUFFERED=1

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2).status==200 else 1)"

CMD ["python", "app.py"]
