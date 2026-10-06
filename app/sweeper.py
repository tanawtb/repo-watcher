"""One sweep: fetch every watched repo, store alerts, diff new/fixed."""

from __future__ import annotations

import threading
from typing import Any

from .config import Config
from .github_api import GitHubClient, RepoInaccessible
from .store import Store

_lock = threading.Lock()


def run_sweep(cfg: Config, store: Store) -> dict[str, Any]:
    """Returns the summary dict for this sweep. Serialized: one sweep at a time."""
    with _lock:
        client = GitHubClient(cfg.token, cfg.api_base)
        sweep_id = store.begin_sweep()
        ok: list[str] = []
        failed: dict[str, str] = {}
        fetched: list[tuple[str, str]] = []  # (repo, source) that returned cleanly
        total = 0
        try:
            for repo in cfg.repos:
                alerts: list[dict[str, Any]] = []
                problems: list[str] = []
                try:
                    alerts += client.dependabot_alerts(repo)
                    fetched.append((repo, "dependabot"))
                except RepoInaccessible as e:
                    problems.append(f"dependabot: {e}")
                except Exception as e:  # noqa: BLE001 - report, never guess
                    problems.append(f"dependabot: {type(e).__name__}: {e}")
                try:
                    alerts += client.code_scanning_alerts(repo)
                    fetched.append((repo, "code_scanning"))
                except RepoInaccessible as e:
                    # 404 = advanced security not enabled: nothing to reconcile.
                    # 403 = permission problem: record it, do NOT reconcile.
                    if "404" not in str(e):
                        problems.append(f"code_scanning: {e}")
                except Exception as e:  # noqa: BLE001
                    problems.append(f"code_scanning: {type(e).__name__}: {e}")
                if problems:
                    failed[repo] = "; ".join(problems)
                for a in alerts:
                    store.upsert_alert(sweep_id, repo, a)
                total += len(alerts)
                if not problems:
                    ok.append(repo)
        finally:
            client.close()
        # Reconcile fixed state ONLY for sources that fetched cleanly this sweep,
        # so an API failure can never mark live alerts as fixed.
        store.mark_fixed(sweep_id, fetched)
        store.finish_sweep(sweep_id, ok, failed, total)
        return store.summary(sweep_id)
