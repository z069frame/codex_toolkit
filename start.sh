#!/bin/sh
# Start both web UI and TG bot
# Bot runs in background; web in foreground (Railway health check needs it)

if [ -n "$TG_BOT_TOKEN" ]; then
    echo "Starting TG bot..."
    python -m bot.tg_bot &
fi

echo "Starting web UI on port ${PORT:-8000}..."
exec uvicorn web.app:app --host 0.0.0.0 --port ${PORT:-8000}
