FROM python:3.11-slim

WORKDIR /app

# Install dependencies first — separate layer for better build caching.
# If only main.py changes, this layer doesn't need to rebuild.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY main.py .

# Run as non-root user — security best practice.
# Running containers as root means a container escape gives the attacker root on the host.
RUN useradd --create-home --shell /bin/bash appuser
USER appuser

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
