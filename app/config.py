"""Configuration from environment / .env. No secrets in tracked files."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader: KEY=VALUE lines, '#' comments. Does not override real env."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip("'\"")
        if key and key not in os.environ:
            os.environ[key] = value


@dataclass
class Config:
    token: str
    repos: list[str]
    api_base: str = "https://api.github.com"
    sweep_times: list[str] = field(default_factory=lambda: ["09:30", "15:30", "17:30"])
    db_path: str = "repo_watcher.db"
    host: str = "127.0.0.1"
    port: int = 8000


def load_config() -> Config:
    _load_dotenv(ROOT / ".env")
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token:
        raise SystemExit("GITHUB_TOKEN missing. Copy .env.example to .env and fill it in.")
    repos = [r.strip() for r in os.environ.get("REPOS", "").split(",") if r.strip()]
    if not repos:
        raise SystemExit("REPOS missing. List owner/name repos to watch, comma-separated.")
    bad = [r for r in repos if r.count("/") != 1]
    if bad:
        raise SystemExit(f"REPOS entries must be owner/name: {bad}")
    times = [t.strip() for t in os.environ.get("SWEEP_TIMES", "09:30,15:30,17:30").split(",") if t.strip()]
    for t in times:
        hh, _, mm = t.partition(":")
        if not (hh.isdigit() and mm.isdigit() and 0 <= int(hh) < 24 and 0 <= int(mm) < 60):
            raise SystemExit(f"SWEEP_TIMES entries must be HH:MM 24h: {t!r}")
    return Config(
        token=token,
        repos=repos,
        api_base=os.environ.get("GITHUB_API_BASE", "https://api.github.com").rstrip("/"),
        sweep_times=times,
        db_path=os.environ.get("DB_PATH", "repo_watcher.db"),
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "8000")),
    )
