FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py policies.py ./

RUN useradd --create-home --shell /bin/bash appuser
USER appuser

EXPOSE 8443

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8443", \
     "--ssl-keyfile", "/etc/webhook/tls/tls.key", \
     "--ssl-certfile", "/etc/webhook/tls/tls.crt"]
