FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    wget \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Preserve backend module structure
COPY . /app/backend

ENV PYTHONPATH=/app

RUN pip install --no-cache-dir -r backend/requirements.txt

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "backend.gateway.main:app", "--host", "0.0.0.0", "--port", "8000"]