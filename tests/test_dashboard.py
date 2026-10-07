"""Theme persistence: the server must render the saved theme on first byte."""

from __future__ import annotations

import tempfile
import unittest

from fastapi.testclient import TestClient

from app.config import Config
from app.main import create_app
from app.store import Store


class ThemeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        cfg = Config(token="t", repos=["octo-org/web-app"], db_path=f"{self.tmp.name}/test.db")
        self.client = TestClient(create_app(cfg))

    def _theme(self, cookie: str | None = None) -> str:
        headers = {"Cookie": cookie} if cookie else {}
        html = self.client.get("/", headers=headers).text
        return html.split('data-theme="', 1)[1].split('"', 1)[0]

    def test_default_is_dark(self) -> None:
        self.assertEqual("dark", self._theme())

    def test_saved_light_theme_renders_on_first_byte(self) -> None:
        self.assertEqual("light", self._theme("rw-theme=light"))

    def test_invalid_theme_falls_back_to_dark(self) -> None:
        self.assertEqual("dark", self._theme("rw-theme=%3Cscript%3E"))


class RepoReportTest(unittest.TestCase):
    """Clicking a repo name must land on that repo's dependency report."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        cfg = Config(token="t", repos=["octo-org/web-app"], db_path=f"{self.tmp.name}/test.db")
        self.store = Store(f"{self.tmp.name}/test.db")
        self.client = TestClient(create_app(cfg))

    def test_dashboard_repo_names_link_to_report(self) -> None:
        html = self.client.get("/").text
        self.assertIn('href="/repo/octo-org/web-app"', html)

    def test_report_page_renders_repo_alerts(self) -> None:
        self.store.begin_sweep()  # sweep_id 1
        self.store.upsert_alert(1, "octo-org/web-app", {
            "source": "dependabot", "number": 7, "severity": "critical", "package": "left-pad",
            "manifest": "package.json", "vulnerable_range": "<2.0.0", "first_patched": "2.0.0",
            "title": "Prototype pollution", "cve": "CVE-2024-1234", "html_url": "https://gh/x",
        })
        # finish_sweep commits the upsert; the app's own Store connection only
        # sees committed rows.
        self.store.finish_sweep(1, ["octo-org/web-app"], {}, 1)
        resp = self.client.get("/repo/octo-org/web-app")
        self.assertEqual(200, resp.status_code)
        self.assertIn("left-pad", resp.text)
        self.assertIn("CVE-2024-1234", resp.text)
        self.assertIn("Prototype pollution", resp.text)

    def test_report_matches_alert_casing_of_stored_repo(self) -> None:
        # alerts keep their original casing; the repos PK is NOCASE.
        self.store.add_repo("Acme/Web-App")
        self.store.begin_sweep()
        self.store.upsert_alert(1, "Acme/Web-App", {
            "source": "dependabot", "number": 1, "severity": "high", "package": "pkg",
            "manifest": "", "vulnerable_range": "", "first_patched": None,
            "title": "", "cve": "", "html_url": "",
        })
        self.store.finish_sweep(1, ["Acme/Web-App"], {}, 1)
        resp = self.client.get("/repo/acme/web-app")  # lowercase URL
        self.assertEqual(200, resp.status_code)
        self.assertIn("pkg", resp.text)

    def test_report_links_to_github_security_page(self) -> None:
        html = self.client.get("/repo/octo-org/web-app").text
        self.assertIn('href="https://github.com/octo-org/web-app/security"', html)

    def test_report_repo_url_follows_ghes_api_base(self) -> None:
        cfg = Config(token="t", repos=["octo-org/web-app"],
                     api_base="https://ghe.example.com/api/v3",
                     db_path=f"{self.tmp.name}/ghes.db")
        client = TestClient(create_app(cfg))
        html = client.get("/repo/octo-org/web-app").text
        self.assertIn('href="https://ghe.example.com/octo-org/web-app/security"', html)

    def test_dashboard_title_not_blank(self) -> None:
        self.assertIn("<title>repo-watcher</title>", self.client.get("/").text)

    def test_report_title_is_repo(self) -> None:
        html = self.client.get("/repo/octo-org/web-app").text
        self.assertIn("<title>octo-org/web-app · repo-watcher</title>", html)

    def test_null_first_patched_renders_unavailable(self) -> None:
        self.store.begin_sweep()
        self.store.upsert_alert(1, "octo-org/web-app", {
            "source": "dependabot", "number": 4, "severity": "high", "package": "dep",
            "manifest": "", "vulnerable_range": ">=1.0 <1.2", "first_patched": None,
            "title": "", "cve": "", "html_url": "",
        })
        self.store.finish_sweep(1, ["octo-org/web-app"], {}, 1)
        html = self.client.get("/repo/octo-org/web-app").text
        self.assertIn("unavailable", html)
        self.assertNotIn("no patch", html)

    def test_zero_alerts_failed_last_sweep_is_unknown_not_clear(self) -> None:
        self.store.begin_sweep()
        self.store.finish_sweep(1, [], {"octo-org/web-app": "403"}, 0)
        html = self.client.get("/repo/octo-org/web-app").text
        self.assertIn('data-state="failed"', html)
        self.assertIn("could not read", html)  # the unknote banner

    def test_zero_alerts_never_swept_is_unknown_not_clear(self) -> None:
        self.store.begin_sweep()
        self.store.finish_sweep(1, ["octo-org/web-app"], {}, 0)
        self.store.add_repo("octo-org/brand-new")  # added after the only sweep
        html = self.client.get("/repo/octo-org/brand-new").text
        self.assertIn('data-state="never"', html)

    def test_unknown_repo_is_404(self) -> None:
        self.assertEqual(404, self.client.get("/repo/nobody/nothing").status_code)


if __name__ == "__main__":
    unittest.main()
