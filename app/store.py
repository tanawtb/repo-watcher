"""SQLite storage: sweeps + alerts with new/fixed diffing."""

from __future__ import annotations

from datetime import datetime, timezone
import sqlite3
import threading
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS sweeps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  repos_ok TEXT NOT NULL DEFAULT '',
  repos_failed TEXT NOT NULL DEFAULT '',
  total_open INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  repo TEXT NOT NULL,
  source TEXT NOT NULL,
  number INTEGER NOT NULL,
  severity TEXT NOT NULL,
  package TEXT NOT NULL DEFAULT '',
  manifest TEXT NOT NULL DEFAULT '',
  vulnerable_range TEXT NOT NULL DEFAULT '',
  first_patched TEXT,
  title TEXT NOT NULL DEFAULT '',
  cve TEXT NOT NULL DEFAULT '',
  html_url TEXT NOT NULL DEFAULT '',
  first_seen_sweep INTEGER NOT NULL,
  last_seen_sweep INTEGER NOT NULL,
  fixed_sweep INTEGER,
  UNIQUE (repo, source, number)
);
CREATE INDEX IF NOT EXISTS idx_alerts_last_seen ON alerts (last_seen_sweep);
"""

SEVERITIES = ("critical", "high", "medium", "low")


def _sync(fn):
    """Serialize access to the shared sqlite connection across threads."""
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return fn(self, *args, **kwargs)
    return wrapper


class Store:
    def __init__(self, path: str | Path) -> None:
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.RLock()
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    @_sync
    def begin_sweep(self, started_at: str | None = None) -> int:
        cur = self._conn.execute(
            "INSERT INTO sweeps (started_at) VALUES (?)", (started_at or self._now(),)
        )
        self._conn.commit()
        return int(cur.lastrowid)

    @_sync
    def finish_sweep(
        self, sweep_id: int, ok: list[str], failed: dict[str, str], total_open: int
    ) -> None:
        failed_txt = "; ".join(f"{r}: {why}" for r, why in failed.items())
        self._conn.execute(
            "UPDATE sweeps SET finished_at=?, repos_ok=?, repos_failed=?, total_open=? WHERE id=?",
            (self._now(), ",".join(ok), failed_txt, total_open, sweep_id),
        )
        self._conn.commit()

    @_sync
    def upsert_alert(self, sweep_id: int, repo: str, a: dict[str, Any]) -> None:
        self._conn.execute(
            """INSERT INTO alerts
               (repo, source, number, severity, package, manifest, vulnerable_range,
                first_patched, title, cve, html_url, first_seen_sweep, last_seen_sweep)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT (repo, source, number) DO UPDATE SET
                 severity=excluded.severity, package=excluded.package,
                 manifest=excluded.manifest, vulnerable_range=excluded.vulnerable_range,
                 first_patched=excluded.first_patched, title=excluded.title,
                 cve=excluded.cve, html_url=excluded.html_url,
                 last_seen_sweep=excluded.last_seen_sweep, fixed_sweep=NULL""",
            (
                repo, a["source"], a["number"], a["severity"], a["package"], a["manifest"],
                a["vulnerable_range"], a["first_patched"], a["title"], a["cve"],
                a["html_url"], sweep_id, sweep_id,
            ),
        )

    @_sync
    def mark_fixed(self, sweep_id: int) -> None:
        """Alerts not seen in the newest sweep are fixed (or closed)."""
        self._conn.execute(
            "UPDATE alerts SET fixed_sweep=? WHERE fixed_sweep IS NULL AND last_seen_sweep<?",
            (sweep_id, sweep_id),
        )
        self._conn.commit()

    @_sync
    def latest_sweep_id(self) -> int | None:
        row = self._conn.execute("SELECT MAX(id) m FROM sweeps WHERE finished_at IS NOT NULL").fetchone()
        return row["m"]

    @_sync
    def previous_sweep_id(self, sweep_id: int) -> int | None:
        row = self._conn.execute(
            "SELECT MAX(id) p FROM sweeps WHERE finished_at IS NOT NULL AND id<?", (sweep_id,)
        ).fetchone()
        return row["p"]

    @_sync
    def open_alerts(self, sweep_id: int) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM alerts WHERE fixed_sweep IS NULL AND last_seen_sweep=? ORDER BY repo, source, number",
            (sweep_id,),
        ).fetchall()

    @_sync
    def summary(self, sweep_id: int) -> dict[str, Any]:
        rows = self.open_alerts(sweep_id)
        by_sev = {s: 0 for s in SEVERITIES}
        by_repo: dict[str, dict[str, int]] = {}
        by_source = {"dependabot": 0, "code_scanning": 0}
        for r in rows:
            by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + 1
            by_source[r["source"]] = by_source.get(r["source"], 0) + 1
            d = by_repo.setdefault(r["repo"], {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0})
            d["total"] += 1
            if r["severity"] in d:
                d[r["severity"]] += 1
        prev = self.previous_sweep_id(sweep_id)
        new_n = fixed_n = 0
        if prev is not None:
            new_n = self._conn.execute(
                "SELECT COUNT(*) c FROM alerts WHERE first_seen_sweep=?", (sweep_id,)
            ).fetchone()["c"]
            fixed_n = self._conn.execute(
                "SELECT COUNT(*) c FROM alerts WHERE fixed_sweep=?", (sweep_id,)
            ).fetchone()["c"]
        sweep = self._conn.execute("SELECT * FROM sweeps WHERE id=?", (sweep_id,)).fetchone()
        return {
            "sweep_id": sweep_id,
            "started_at": sweep["started_at"],
            "finished_at": sweep["finished_at"],
            "repos_ok": [r for r in sweep["repos_ok"].split(",") if r],
            "repos_failed": sweep["repos_failed"],
            "total": len(rows),
            "by_severity": by_sev,
            "by_source": by_source,
            "by_repo": by_repo,
            "new": new_n,
            "fixed": fixed_n,
        }

    @_sync
    def sweeps(self, limit: int = 20) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM sweeps ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
