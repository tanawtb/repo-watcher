"""Repo CRUD: validation, duplicates, rename cascade, delete."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.store import (
    DuplicateRepo,
    InvalidRepo,
    Store,
    UnknownRepo,
    validate_repo_name,
)


class ValidateTest(unittest.TestCase):
    def test_accepts_and_normalizes(self) -> None:
        self.assertEqual("a/b", validate_repo_name("  a/b  "))
        self.assertEqual("a/b", validate_repo_name("a/b/"))

    def test_rejects_bad_shapes(self) -> None:
        for bad in ("", "justname", "a/b/c", "/b", "a/", "a b/c", "a/b c", "or g e/r"):
            with self.subTest(bad=bad), self.assertRaises(InvalidRepo):
                validate_repo_name(bad)


class RepoCrudTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(Path(self.tmp.name) / "test.db")

    def test_add_list_get(self) -> None:
        row = self.store.add_repo("Acme/Web-App", "flagship")
        self.assertEqual("Acme/Web-App", row["name"])
        self.assertEqual("flagship", row["note"])
        self.assertEqual(["Acme/Web-App"], self.store.repo_names())
        self.assertEqual("Acme/Web-App", self.store.get_repo("Acme/Web-App")["name"])

    def test_duplicate_rejected_case_insensitively(self) -> None:
        self.store.add_repo("acme/web-app")
        with self.assertRaises(DuplicateRepo):
            self.store.add_repo("ACME/Web-App")

    def test_update_note_and_rename(self) -> None:
        self.store.add_repo("acme/web-app")
        self.store.set_favorite("acme/web-app", True)
        self.store.upsert_alert(1, "acme/web-app", {
            "source": "dependabot", "number": 1, "severity": "high", "package": "x",
            "manifest": "", "vulnerable_range": "", "first_patched": None,
            "title": "", "cve": "", "html_url": "",
        })
        row = self.store.update_repo("acme/web-app", new_name="acme2/web-app", note="moved")
        self.assertEqual("acme2/web-app", row["name"])
        self.assertEqual("moved", row["note"])
        # history follows the repo
        self.assertEqual("acme2/web-app", self.store.open_alerts()[0]["repo"])
        self.assertIn("acme2/web-app", self.store.favorite_repos())

    def test_rename_to_existing_rejected(self) -> None:
        self.store.add_repo("a/x")
        self.store.add_repo("b/y")
        with self.assertRaises(DuplicateRepo):
            self.store.update_repo("a/x", new_name="b/y")

    def test_rename_same_name_is_noop(self) -> None:
        self.store.add_repo("a/x")
        row = self.store.update_repo("a/x", new_name="a/x")
        self.assertEqual("a/x", row["name"])

    def test_update_unknown_rejected(self) -> None:
        with self.assertRaises(UnknownRepo):
            self.store.update_repo("no/such", note="hi")

    def test_delete_removes_repo_and_favorite(self) -> None:
        self.store.add_repo("a/x")
        self.store.set_favorite("a/x", True)
        self.store.delete_repo("a/x")
        self.assertIsNone(self.store.get_repo("a/x"))
        self.assertNotIn("a/x", self.store.favorite_repos())

    def test_delete_unknown_rejected(self) -> None:
        with self.assertRaises(UnknownRepo):
            self.store.delete_repo("no/such")

    def test_seed_happens_once_even_if_all_deleted(self) -> None:
        self.store.seed_repos(["a/x", "b/y"])
        self.store.delete_repo("a/x")
        self.store.delete_repo("b/y")
        self.store.seed_repos(["a/x", "b/y"])  # restart with same .env
        self.assertEqual([], self.store.repo_names())

    def test_mixed_case_rename_cascades_to_history(self) -> None:
        # Stored lowercase; caller uses different casing. alerts/favorites are
        # case-sensitive, so the cascade must use the stored canonical name.
        self.store.add_repo("acme/web-app")
        self.store.set_favorite("acme/web-app", True)
        self.store.upsert_alert(1, "acme/web-app", {
            "source": "dependabot", "number": 1, "severity": "high", "package": "x",
            "manifest": "", "vulnerable_range": "", "first_patched": None,
            "title": "", "cve": "", "html_url": "",
        })
        self.store.update_repo("ACME/Web-App", new_name="acme2/web-app")
        self.assertEqual("acme2/web-app", self.store.open_alerts()[0]["repo"])
        self.assertIn("acme2/web-app", self.store.favorite_repos())

    def test_unwatched_repo_alerts_hidden_until_readded(self) -> None:
        self.store.add_repo("a/x")
        self.store.upsert_alert(1, "a/x", {
            "source": "dependabot", "number": 1, "severity": "high", "package": "x",
            "manifest": "", "vulnerable_range": "", "first_patched": None,
            "title": "", "cve": "", "html_url": "",
        })
        self.assertEqual(1, len(self.store.open_alerts()))
        self.store.delete_repo("a/x")
        self.assertEqual([], self.store.open_alerts())  # ghost alerts gone
        self.store.add_repo("a/x")
        self.assertEqual(1, len(self.store.open_alerts()))  # history preserved

    def test_seed_is_idempotent_and_skips_invalid(self) -> None:
        self.store.seed_repos(["a/x", "bad name", "a/x", "b/y"])
        self.assertEqual(["a/x", "b/y"], self.store.repo_names())
        self.store.seed_repos(["a/x"])
        self.assertEqual(["a/x", "b/y"], self.store.repo_names())


if __name__ == "__main__":
    unittest.main()
