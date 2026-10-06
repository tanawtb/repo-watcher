"""FastAPI app: API, dashboard, and wall-clock sweep scheduler."""

from __future__ import annotations

import threading
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

from .config import Config, load_config
from .store import Store
from .sweeper import run_sweep

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def create_app(cfg: Config | None = None) -> FastAPI:
    cfg = cfg or load_config()
    store = Store(cfg.db_path)
    app = FastAPI(title="repo-watcher", docs_url=None, redoc_url=None)

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> HTMLResponse:
        sweep_id = store.latest_sweep_id()
        summary = store.summary(sweep_id) if sweep_id else None
        alerts = [dict(r) for r in store.open_alerts(sweep_id)] if sweep_id else []
        sweeps = [dict(r) for r in store.sweeps()]
        return TEMPLATES.TemplateResponse(
            request,
            "dashboard.html",
            {
                "summary": summary,
                "alerts": alerts,
                "sweeps": sweeps,
                "repos": cfg.repos,
                "sweep_times": cfg.sweep_times,
            },
        )

    @app.get("/api/summary")
    def api_summary() -> dict:
        sweep_id = store.latest_sweep_id()
        if not sweep_id:
            return {"sweep_id": None, "total": 0, "by_severity": {}, "by_repo": {}, "new": 0, "fixed": 0}
        return store.summary(sweep_id)

    @app.get("/api/alerts")
    def api_alerts() -> list[dict]:
        sweep_id = store.latest_sweep_id()
        return [dict(r) for r in store.open_alerts(sweep_id)] if sweep_id else []

    @app.get("/api/sweeps")
    def api_sweeps() -> list[dict]:
        return [dict(r) for r in store.sweeps()]

    @app.post("/api/sweep")
    def api_sweep() -> dict:
        return run_sweep(cfg, store)

    _start_scheduler(cfg, store)
    return app


def _start_scheduler(cfg: Config, store: Store) -> None:
    """Check every 30s; fire a sweep when the clock hits a configured time (once per minute)."""

    def loop() -> None:
        fired: set[str] = set()
        while True:
            now = datetime.now()
            key = now.strftime("%Y-%m-%d %H:%M")
            if now.strftime("%H:%M") in cfg.sweep_times and key not in fired:
                fired.add(key)
                if len(fired) > 288:
                    fired.clear()
                try:
                    run_sweep(cfg, store)
                except Exception:  # noqa: BLE001 - scheduler must survive
                    pass
            threading.Event().wait(30)

    threading.Thread(target=loop, daemon=True, name="sweep-scheduler").start()
