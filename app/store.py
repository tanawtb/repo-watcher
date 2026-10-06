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
  branch TEXT NOT NULL DEFAULT '',
  first_seen_sweep INTEGER NOT NULL,
  last_seen_sweep INTEGER NOT NULL,
  fixed_sweep INTEGER,
  UNIQUE (repo, source, number)
);
CREATE INDEX IF NOT EXISTS idx_alerts_last_seen ON alerts (last_seen_sweep);
CREATE TABLE IF NOT EXISTS favorites (
  repo TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS repos (
  name TEXT PRIMARY KEY COLLATE NOCASE,
  added_at TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
"""

SEVERITIES = ("critical", "high", "medium", "low")


class RepoError(Exception):
    """Base for repo CRUD failures; the API maps these to HTTP status codes."""


class InvalidRepo(RepoError):
    pass


class DuplicateRepo(RepoError):
    pass


class UnknownRepo(RepoError):
    pass


def validate_repo_name(name: str) -> str:
    """Normalize and validate an owner/name GitHub repo slug."""
    cleaned = (name or "").strip().strip("/")
    if cleaned.count("/") != 1:
        raise InvalidRepo(f"repo must be owner/name, got {name!r}")
    owner, _, repo = cleaned.partition("/")
    for part in (owner, repo):
        if not part:
            raise InvalidRepo(f"repo must be owner/name, got {name!r}")
        if not all(c.isalnum() or c in "._-" for c in part):
            raise InvalidRepo(f"owner and name may only contain letters, digits, . _ -: {name!r}")
    return f"{owner}/{repo}"


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
        cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(alerts)")}
        if "branch" not in cols:  # pre-existing DBs get the column added in place
            self._conn.execute("ALTER TABLE alerts ADD COLUMN branch TEXT NOT NULL DEFAULT ''")
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
                first_patched, title, cve, html_url, branch, first_seen_sweep, last_seen_sweep)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT (repo, source, number) DO UPDATE SET
                 severity=excluded.severity, package=excluded.package,
                 manifest=excluded.manifest, vulnerable_range=excluded.vulnerable_range,
                 first_patched=excluded.first_patched, title=excluded.title,
                 cve=excluded.cve, html_url=excluded.html_url, branch=excluded.branch,
                 last_seen_sweep=excluded.last_seen_sweep, fixed_sweep=NULL""",
            (
                repo, a["source"], a["number"], a["severity"], a["package"], a["manifest"],
                a["vulnerable_range"], a["first_patched"], a["title"], a["cve"],
                a["html_url"], a.get("branch", ""), sweep_id, sweep_id,
            ),
        )

    @_sync
    def mark_fixed(self, sweep_id: int, fetched: list[tuple[str, str]]) -> None:
        """Mark alerts fixed only where this sweep fetched that (repo, source) cleanly.

        A failed fetch must never reconcile: its alerts stay open so a live
        vulnerability is not silently hidden.
        """
        for repo, source in fetched:
            self._conn.execute(
                "UPDATE alerts SET fixed_sweep=? "
                "WHERE fixed_sweep IS NULL AND last_seen_sweep<? AND repo=? AND source=?",
                (sweep_id, sweep_id, repo, source),
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
    def open_alerts(self) -> list[sqlite3.Row]:
        """Open alerts for watched repos — including repos whose last fetch failed.

        Alerts of unwatched repos stay in history (re-add the repo and they
        return) but never show as open: nothing sweeps them, so they could
        never reconcile.
        """
        return self._conn.execute(
            "SELECT * FROM alerts a WHERE a.fixed_sweep IS NULL "
            "AND EXISTS (SELECT 1 FROM repos r WHERE r.name = a.repo COLLATE NOCASE) "
            "ORDER BY a.repo, CASE a.severity "
            "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
            "WHEN 'low' THEN 3 ELSE 4 END, a.number"
        ).fetchall()

    @_sync
    def favorite_repos(self) -> set[str]:
        return {r["repo"] for r in self._conn.execute("SELECT repo FROM favorites")}

    @_sync
    def set_favorite(self, repo: str, on: bool) -> None:
        if on:
            self._conn.execute("INSERT OR IGNORE INTO favorites (repo) VALUES (?)", (repo,))
        else:
            self._conn.execute("DELETE FROM favorites WHERE repo = ?", (repo,))
        self._conn.commit()

    # ---- watched repos (the sweep target list lives here, not .env) ----

    @_sync
    def list_repos(self) -> list[sqlite3.Row]:
        return self._conn.execute("SELECT * FROM repos ORDER BY name COLLATE NOCASE").fetchall()

    @_sync
    def repo_names(self) -> list[str]:
        return [r["name"] for r in self._conn.execute("SELECT name FROM repos ORDER BY name COLLATE NOCASE")]

    @_sync
    def get_repo(self, name: str) -> sqlite3.Row | None:
        return self._conn.execute("SELECT * FROM repos WHERE name = ?", (name,)).fetchone()

    @_sync
    def add_repo(self, name: str, note: str = "") -> sqlite3.Row:
        clean = validate_repo_name(name)
        if self._conn.execute("SELECT 1 FROM repos WHERE name = ?", (clean,)).fetchone():
            raise DuplicateRepo(f"{clean} is already watched")
        self._conn.execute(
            "INSERT INTO repos (name, added_at, note) VALUES (?, ?, ?)",
            (clean, self._now(), (note or "").strip()),
        )
        self._conn.commit()
        return self._conn.execute("SELECT * FROM repos WHERE name = ?", (clean,)).fetchone()

    @_sync
    def update_repo(self, name: str, *, new_name: str | None = None, note: str | None = None) -> sqlite3.Row:
        clean = validate_repo_name(name)
        row = self._conn.execute("SELECT name FROM repos WHERE name = ?", (clean,)).fetchone()
        if not row:
            raise UnknownRepo(f"{clean} is not watched")
        stored = row["name"]  # canonical casing; the PK match is NOCASE
        if new_name is not None:
            target = validate_repo_name(new_name)
            if target.lower() != stored.lower() and self._conn.execute(
                "SELECT 1 FROM repos WHERE name = ?", (target,)
            ).fetchone():
                raise DuplicateRepo(f"{target} is already watched")
            if target.lower() != stored.lower():
                # Rename cascades to alerts/favorites so history follows the repo.
                # alerts/favorites are case-sensitive, so match the stored casing.
                self._conn.execute("UPDATE alerts SET repo=? WHERE repo=?", (target, stored))
                self._conn.execute("UPDATE favorites SET repo=? WHERE repo=?", (target, stored))
                self._conn.execute("UPDATE repos SET name=? WHERE name=?", (target, stored))
                stored = target
        if note is not None:
            self._conn.execute("UPDATE repos SET note=? WHERE name=?", (note.strip(), stored))
        self._conn.commit()
        return self._conn.execute("SELECT * FROM repos WHERE name = ?", (stored,)).fetchone()

    @_sync
    def delete_repo(self, name: str) -> None:
        clean = validate_repo_name(name)
        row = self._conn.execute("SELECT name FROM repos WHERE name = ?", (clean,)).fetchone()
        if not row:
            raise UnknownRepo(f"{clean} is not watched")
        self._conn.execute("DELETE FROM repos WHERE name = ?", (row["name"],))
        self._conn.execute("DELETE FROM favorites WHERE repo = ?", (row["name"],))
        self._conn.commit()

    @_sync
    def seed_repos(self, names: list[str]) -> None:
        """Import .env REPOS exactly once; the DB is the source of truth after.

        The marker persists even if every repo is later deleted, so a
        deliberately emptied list never resurrects on restart.
        """
        if self._conn.execute("SELECT 1 FROM meta WHERE key = 'repos_seeded'").fetchone():
            return
        for raw in names:
            try:
                clean = validate_repo_name(raw)
            except InvalidRepo:
                continue
            self._conn.execute(
                "INSERT OR IGNORE INTO repos (name, added_at, note) VALUES (?, ?, '')",
                (clean, self._now()),
            )
        self._conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('repos_seeded', ?)", (self._now(),)
        )
        self._conn.commit()

    @_sync
    def summary(self, sweep_id: int) -> dict[str, Any]:
        rows = self.open_alerts()
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
