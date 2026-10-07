"""FastAPI app: API, dashboard, MCP server, and wall-clock sweep scheduler."""

from __future__ import annotations

import threading
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastmcp.server.http import HostOriginGuardMiddleware
from starlette.requests import Request
from starlette.types import ASGIApp, Receive, Scope, Send

from .config import Config, load_config
from .mcp_server import build_mcp
from .store import DuplicateRepo, RepoError, Store, UnknownRepo
from .sweeper import run_sweep

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


class _McpGuard:
    """Host/Origin guard for /mcp only (FastAPI routes otherwise unguarded)."""

    def __init__(self, app: ASGIApp, allowed_hosts: list[str] | None = None) -> None:
        self.guard = HostOriginGuardMiddleware(app, allowed_hosts=allowed_hosts, mode="strict")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope.get("path", "").startswith("/mcp"):
            await self.guard(scope, receive, send)
            return
        await self.guard.app(scope, receive, send)


def _theme_of(request: Request) -> str:
    theme = request.cookies.get("rw-theme", "dark")
    return theme if theme in ("dark", "light") else "dark"


def create_app(cfg: Config | None = None) -> FastAPI:
    cfg = cfg or load_config()
    store = Store(cfg.db_path)
    store.seed_repos(cfg.repos)  # first-run import of .env REPOS; DB is the source of truth

    mcp_app = build_mcp(store, lambda: run_sweep(cfg, store)).http_app(
        path="/mcp", stateless_http=True
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        async with mcp_app.lifespan(_app):
            yield

    app = FastAPI(title="repo-watcher", docs_url=None, redoc_url=None, lifespan=lifespan)
    # Copy routes instead of mount() so POST /mcp works without a redirect.
    app.router.routes.extend(mcp_app.routes)
    # routes.extend() skips mcp_app's middleware stack, so re-apply FastMCP's
    # Host/Origin guard (spec-required DNS-rebinding/hotlinking protection)
    # to /mcp only. Strict: validate Host on every /mcp request, Origin when
    # present. Bind address is auto-allowed; add MCP_ALLOWED_HOSTS for proxies.
    app.add_middleware(_McpGuard, allowed_hosts=cfg.mcp_allowed_hosts)

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> HTMLResponse:
        theme = _theme_of(request)
        sweep_id = store.latest_sweep_id()
        summary = store.summary(sweep_id) if sweep_id else None
        alerts = []
        if sweep_id:
            rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            alerts = [dict(r, severity_rank=rank.get(r["severity"], 4)) for r in store.open_alerts()]
        sweeps = [dict(r) for r in store.sweeps()]
        favorites = store.favorite_repos()
        return TEMPLATES.TemplateResponse(
            request,
            "dashboard.html",
            {
                "summary": summary,
                "alerts": alerts,
                "sweeps": sweeps,
                "repos": store.list_repos(),
                "sweep_times": cfg.sweep_times,
                "favorites": favorites,
                "theme": theme,
                "page_title": "repo-watcher",
            },
        )

    @app.get("/repo/{name:path}", response_class=HTMLResponse)
    def repo_page(request: Request, name: str) -> HTMLResponse:
        """One repo's dependency report: open alerts, fixed history, sweep state."""
        report = store.repo_report(name)
        if report is None:
            raise HTTPException(status_code=404, detail=f"{name} is not a watched repo")
        return TEMPLATES.TemplateResponse(
            request,
            "report.html",
            {
                "report": report,
                "sweep_times": cfg.sweep_times,
                "theme": _theme_of(request),
                "page_title": f"{report['repo']} · repo-watcher",
                "repo_url": f"{cfg.web_base}/{report['repo']}",
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
        return [dict(r) for r in store.open_alerts()] if sweep_id else []

    @app.get("/api/sweeps")
    def api_sweeps() -> list[dict]:
        return [dict(r) for r in store.sweeps()]

    @app.post("/api/sweep")
    def api_sweep() -> dict:
        return run_sweep(cfg, store)

    @app.post("/api/favorite")
    def api_favorite(payload: dict) -> dict:
        repo = str(payload.get("repo", ""))
        on = bool(payload.get("on", False))
        if not repo:
            return {"ok": False, "error": "repo required"}
        store.set_favorite(repo, on)
        return {"ok": True, "repo": repo, "on": on}

    @app.get("/api/repos")
    def api_repos() -> list[dict]:
        return [dict(r) for r in store.list_repos()]

    @app.post("/api/repos")
    def api_repos_add(payload: dict) -> dict:
        try:
            row = store.add_repo(str(payload.get("name", "")), str(payload.get("note", "")))
        except RepoError as e:
            raise HTTPException(status_code=409 if isinstance(e, DuplicateRepo) else 400, detail=str(e))
        return {"ok": True, "repo": dict(row)}

    @app.patch("/api/repos")
    def api_repos_update(payload: dict) -> dict:
        try:
            row = store.update_repo(
                str(payload.get("name", "")),
                new_name=payload.get("new_name") or None,
                note=payload.get("note") if payload.get("note") is not None else None,
            )
        except RepoError as e:
            raise HTTPException(status_code=404 if isinstance(e, UnknownRepo) else 409 if isinstance(e, DuplicateRepo) else 400, detail=str(e))
        return {"ok": True, "repo": dict(row)}

    @app.delete("/api/repos")
    def api_repos_delete(name: str) -> dict:
        try:
            store.delete_repo(name)
        except RepoError as e:
            raise HTTPException(status_code=404 if isinstance(e, UnknownRepo) else 400, detail=str(e))
        return {"ok": True, "repo": name}

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
