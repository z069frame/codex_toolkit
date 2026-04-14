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

# Start web + bot (bot only if TG_BOT_TOKEN is set)
CMD ["sh", "start.sh"]
