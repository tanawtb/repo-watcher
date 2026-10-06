"""MCP server (Model Context Protocol, streamable HTTP) over the same Store.

Agents connect to http://<host>:<port>/mcp and can list/watch/edit/remove
repos plus read alerts and trigger sweeps. Tools mirror the dashboard's
power; the dashboard and MCP share one SQLite store, so changes are
immediately visible to both.
"""

from __future__ import annotations

from typing import Any

from fastmcp import FastMCP

from .store import DuplicateRepo, InvalidRepo, RepoError, Store, UnknownRepo


def build_mcp(store: Store, sweep_fn: Any) -> FastMCP:
    """sweep_fn: zero-arg callable returning the sweep summary dict."""
    mcp = FastMCP(
        name="repo-watcher",
        instructions=(
            "Watched-repo and security-alert manager for the repo-watcher "
            "dashboard. Use the repo tools to change what is watched; use the "
            "alert tools to read results; trigger_sweep refreshes from GitHub."
        ),
    )

    def _repos() -> list[dict]:
        return [dict(r) for r in store.list_repos()]

    @mcp.tool()
    def list_repos() -> list[dict]:
        """List every watched repo: name, added_at, note."""
        return _repos()

    @mcp.tool()
    def add_repo(name: str, note: str = "") -> dict:
        """Start watching a GitHub repo. name must be owner/name (e.g. acme/web-app)."""
        try:
            row = store.add_repo(name, note)
        except RepoError as e:
            return {"ok": False, "error": str(e)}
        return {"ok": True, "repo": dict(row)}

    @mcp.tool()
    def update_repo(name: str, new_name: str = "", note: str = "") -> dict:
        """Rename a watched repo and/or set its note. Pass empty string to leave a field unchanged."""
        try:
            row = store.update_repo(
                name,
                new_name=new_name or None,
                note=note or None,
            )
        except RepoError as e:
            return {"ok": False, "error": str(e)}
        return {"ok": True, "repo": dict(row)}

    @mcp.tool()
    def remove_repo(name: str) -> dict:
        """Stop watching a repo. Past alerts stay in history; the favorite flag is cleared."""
        try:
            store.delete_repo(name)
        except RepoError as e:
            return {"ok": False, "error": str(e)}
        return {"ok": True, "repo": name}

    @mcp.tool()
    def get_summary() -> dict:
        """Alert totals for the latest sweep: by severity, by source, by repo, new/fixed."""
        sweep_id = store.latest_sweep_id()
        if not sweep_id:
            return {"sweep_id": None, "total": 0, "message": "no sweep has run yet"}
        return store.summary(sweep_id)

    @mcp.tool()
    def list_alerts(repo: str = "") -> list[dict]:
        """Open alerts, optionally filtered to one repo (owner/name)."""
        rows = [dict(r) for r in store.open_alerts()]
        if repo:
            want = repo.strip().lower()
            rows = [r for r in rows if r["repo"].lower() == want]
        return rows

    @mcp.tool()
    def trigger_sweep() -> dict:
        """Fetch alerts from GitHub for every watched repo now. Takes a few seconds."""
        try:
            return {"ok": True, "summary": sweep_fn()}
        except Exception as e:  # noqa: BLE001 - surface, never crash the tool
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    # Keep the error classes importable for tests that assert on them.
    assert DuplicateRepo and InvalidRepo and UnknownRepo
    return mcp
