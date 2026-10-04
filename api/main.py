from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from api.db import init_db

init_db()
app = FastAPI(title="Auth Demo")


@app.get("/api/health")
def health():
    return {"status": "ok"}


# Mounted last so /api routes take priority over static files
WEB_DIR = Path(__file__).parent.parent / "web"
app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")