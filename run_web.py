#!/usr/bin/env python3
"""Launch the web server. Reads PORT from env (default 8000)."""
import os
import uvicorn

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run("web.app:app", host="127.0.0.1", port=port)
