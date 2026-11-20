FROM python:3.13-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl tzdata \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ /app/

RUN useradd -u 1000 -m ca && mkdir -p /data && chown ca:ca /data
USER ca

ENV DATA_DIR=/data \
    PYTHONUNBUFFERED=1
VOLUME /data
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz')"

CMD ["gunicorn", "-b", "0.0.0.0:8080", "-w", "1", "--threads", "4", "--access-logfile", "-", "app:app"]
