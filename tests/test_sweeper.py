"""Reconciliation regression: a failed fetch must never hide a live alert."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import app.sweeper as sweeper
from app.config import Config
from app.github_api import RepoInaccessible
from app.store import Store


def _alert(number: int = 1, severity: str = "high") -> dict:
    return {
        "source": "dependabot",
        "number": number,
        "severity": severity,
        "package": "left-pad",
        "manifest": "package-lock.json",
        "vulnerable_range": "<= 1.0.0",
        "first_patched": "1.0.1",
        "title": "prototype pollution",
        "cve": "CVE-2024-0000",
        "html_url": "https://github.example/x/security/dependabot/1",
        "branch": "develop",
    }


class FakeClient:
    def __init__(
        self,
        dependabot: list[dict] | None = None,
        code_scanning: list[dict] | None = None,
        dependabot_error: Exception | None = None,
        code_scanning_error: Exception | None = None,
    ) -> None:
        self._dep = dependabot or []
        self._cs = code_scanning or []
        self._dep_err = dependabot_error
        self._cs_err = code_scanning_error

    def dependabot_alerts(self, repo: str) -> list[dict]:
        if self._dep_err:
            raise self._dep_err
        return self._dep

    def code_scanning_alerts(self, repo: str) -> list[dict]:
        if self._cs_err:
            raise self._cs_err
        return self._cs

    def close(self) -> None:
        pass


class ReconciliationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(Path(self.tmp.name) / "test.db")
        self.cfg = Config(token="t", repos=["octo-org/web-app"])
        self.store.seed_repos(self.cfg.repos)  # the sweep list lives in the DB

    def _patch(self, fake: FakeClient) -> None:
        patcher = mock.patch.object(sweeper, "GitHubClient", return_value=fake)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_failed_fetch_keeps_live_alert_open(self) -> None:
        # Sweep 1: one open alert recorded.
        self._patch(FakeClient(dependabot=[_alert()]))
        s1 = sweeper.run_sweep(self.cfg, self.store)
        self.assertEqual(1, s1["total"])

        # Sweep 2: the fetch fails (404 on dependabot = inaccessible repo).
        # The alert must NOT be reconciled as fixed.
        self._patch(FakeClient(dependabot_error=RepoInaccessible("HTTP 404", 404)))
        s2 = sweeper.run_sweep(self.cfg, self.store)
        self.assertEqual(1, s2["total"], "failed fetch hid a live alert")
        rows = self.store.open_alerts()
        self.assertEqual(1, len(rows))
        self.assertIsNone(rows[0]["fixed_sweep"])
        self.assertEqual("develop", rows[0]["branch"])
        self.assertIn("octo-org/web-app", s2["repos_failed"])

    def test_code_scanning_403_is_failure_not_reconciled(self) -> None:
        self._patch(FakeClient(dependabot=[], code_scanning=[{**_alert(), "source": "code_scanning"}]))
        sweeper.run_sweep(self.cfg, self.store)

        # 403 = permission problem: record failure, keep the alert open.
        self._patch(FakeClient(dependabot=[], code_scanning_error=RepoInaccessible("HTTP 403", 403)))
        s2 = sweeper.run_sweep(self.cfg, self.store)
        self.assertEqual(1, len(self.store.open_alerts()))
        self.assertIn("octo-org/web-app", s2["repos_failed"])

    def test_code_scanning_404_is_benign_not_a_failure(self) -> None:
        # Advanced security not enabled: 404 is expected, repo stays "ok".
        self._patch(FakeClient(dependabot=[_alert()], code_scanning_error=RepoInaccessible("HTTP 404", 404)))
        s = sweeper.run_sweep(self.cfg, self.store)
        self.assertEqual("", s["repos_failed"])
        self.assertIn("octo-org/web-app", s["repos_ok"])
        self.assertEqual(1, len(self.store.open_alerts()))

    def test_clean_fetch_marks_gone_alert_fixed(self) -> None:
        self._patch(FakeClient(dependabot=[_alert()]))
        sweeper.run_sweep(self.cfg, self.store)

        # Clean fetch with the alert gone: it is genuinely fixed.
        self._patch(FakeClient(dependabot=[], code_scanning=[]))
        s2 = sweeper.run_sweep(self.cfg, self.store)
        self.assertEqual(0, s2["total"])
        self.assertEqual(1, s2["fixed"])
        self.assertEqual([], self.store.open_alerts())


if __name__ == "__main__":
    unittest.main()
