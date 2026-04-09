FROM python:3.11-slim

WORKDIR /app

# System deps for curl_cffi
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libcurl4-openssl-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create output dir
RUN mkdir -p /app/output

EXPOSE 8000

# Railway injects $PORT; default to 8000 for local
CMD uvicorn web.app:app --host 0.0.0.0 --port ${PORT:-8000}
