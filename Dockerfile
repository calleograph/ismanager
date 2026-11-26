FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
WORKDIR /opt/ismanager
RUN apt-get -o Acquire::Retries=3 update && apt-get install -y --no-install-recommends ca-certificates libgomp1 poppler-utils tesseract-ocr tesseract-ocr-eng tesseract-ocr-rus && rm -rf /var/lib/apt/lists/*
COPY requirements*.txt ./
RUN pip install -r requirements.txt && pip check
COPY app/privacy/fetch_models.py /tmp/fetch_models.py
RUN python /tmp/fetch_models.py /opt/nlp
RUN groupadd -g 10001 ismanager && useradd -m -u 10001 -g ismanager ismanager && install -d -o ismanager -g ismanager /data
COPY --chown=10001:10001 VERSION ./
COPY --chown=10001:10001 app ./app
USER 10001:10001
EXPOSE 8443
HEALTHCHECK --interval=10s --timeout=5s --start-period=1m CMD python -c "import ssl, urllib.request; urllib.request.urlopen('https://localhost:8443/healthz', context=ssl._create_unverified_context(), timeout=4).read()"
CMD ["sh","-ec","python -m app.tls && exec gunicorn --certfile /data/tls.pem --keyfile /data/tls.pem --bind 0.0.0.0:8443 --workers 2 --threads 3 --timeout 180 'app:create_app()'"]
