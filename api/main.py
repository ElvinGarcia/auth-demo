from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from api.auth import level0, level0_attacker, level1, level1_attacker, level2, level2_attacker
from api.db import init_db

init_db()
level0.seed()
level1.seed()
level2.seed()

app = FastAPI(title="Auth Demo")
app.include_router(level0.router)
app.include_router(level0_attacker.router)
app.include_router(level1.router)
app.include_router(level1_attacker.router)
app.include_router(level2.router)
app.include_router(level2_attacker.router)


@app.get("/api/health")
def health():
    return {"status": "ok"}


# Mounted last so /api routes take priority over static files
WEB_DIR = Path(__file__).parent.parent / "web"
app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")