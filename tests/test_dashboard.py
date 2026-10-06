"""Theme persistence: the server must render the saved theme on first byte."""

from __future__ import annotations

import tempfile
import unittest

from fastapi.testclient import TestClient

from app.config import Config
from app.main import create_app


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


if __name__ == "__main__":
    unittest.main()
