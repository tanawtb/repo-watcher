"""Read-only GitHub fetchers for Dependabot and code-scanning alerts."""

from __future__ import annotations

import re
from typing import Any

import httpx

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


class RepoInaccessible(Exception):
    """404/403 on a repo: not visible to this token. Never guess its state.

    `status` carries the HTTP status so callers can distinguish a benign 404
    (feature not enabled) from a 403 permission failure without string matching.
    """

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class GitHubClient:
    def __init__(self, token: str, api_base: str = "https://api.github.com") -> None:
        self._base = api_base
        self._client = httpx.Client(
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=30.0,
        )

    def close(self) -> None:
        self._client.close()

    def _paginate(self, path: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        url: str | None = f"{self._base}{path}"
        while url:
            resp = self._client.get(url)
            if resp.status_code in (403, 404):
                raise RepoInaccessible(f"HTTP {resp.status_code}", resp.status_code)
            resp.raise_for_status()
            page = resp.json()
            if isinstance(page, dict):  # error envelope
                raise RepoInaccessible(page.get("message", "unknown error"), resp.status_code)
            items.extend(page)
            link = resp.headers.get("Link", "")
            url = None
            for part in link.split(","):
                if 'rel="next"' in part:
                    url = part[part.find("<") + 1 : part.find(">")]
                    break
        return items

    def dependabot_alerts(self, repo: str) -> list[dict[str, Any]]:
        raw = self._paginate(f"/repos/{repo}/dependabot/alerts?state=open&per_page=100")
        out = []
        for a in raw:
            dep = a.get("dependency", {})
            pkg = dep.get("package", {})
            adv = a.get("security_advisory", {})
            vuln = a.get("security_vulnerability", {}) or {}
            patched = (vuln.get("first_patched_version") or {}).get("identifier")
            out.append(
                {
                    "source": "dependabot",
                    "number": a["number"],
                    "severity": (vuln.get("severity") or adv.get("severity") or "unknown"),
                    "package": pkg.get("name", ""),
                    "manifest": dep.get("manifest_path", ""),
                    "vulnerable_range": vuln.get("vulnerable_version_range", ""),
                    "first_patched": patched,
                    "title": adv.get("summary", ""),
                    "cve": adv.get("cve_id") or "",
                    "html_url": a.get("html_url", ""),
                }
            )
        return out

    def code_scanning_alerts(self, repo: str) -> list[dict[str, Any]]:
        raw = self._paginate(f"/repos/{repo}/code-scanning/alerts?state=open&per_page=100")
        out = []
        for a in raw:
            rule = a.get("rule", {}) or {}
            tags = rule.get("tags") or []
            cve = next((t for t in tags if CVE_RE.fullmatch(t)), "")
            sev = rule.get("security_severity_level") or rule.get("severity") or "unknown"
            tool = (a.get("tool") or {}).get("name", "")
            out.append(
                {
                    "source": "code_scanning",
                    "number": a["number"],
                    "severity": sev,
                    "package": tool,
                    "manifest": ((a.get("most_recent_instance") or {}).get("ref") or ""),
                    "vulnerable_range": rule.get("id", ""),
                    "first_patched": None,
                    "title": rule.get("description") or "",
                    "cve": cve,
                    "html_url": a.get("html_url", ""),
                }
            )
        return out
