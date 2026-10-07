# repo-watcher

Self-hosted watcher that sweeps **GitHub Dependabot alerts** (and code-scanning alerts) for a list of repositories you manage from the dashboard or over MCP, stores every sweep in SQLite, and shows the current state on a minimal glass dashboard.

No local scanners. GitHub's own security findings are the source of truth.

## Features

- Sweeps Dependabot + code-scanning alerts for every watched repo — works with GitHub.com or GitHub Enterprise (`GITHUB_API_BASE`). The watched list lives in SQLite; add/edit/remove from the dashboard, the API, or any MCP client.
- SQLite history: every sweep is recorded; the dashboard shows open alerts, new-since-last-sweep, and fixed-since-last-sweep.
- Scheduled sweeps at wall-clock times you set (`SWEEP_TIMES=09:30,15:30,17:30`), plus manual "sweep now".
- Dashboard: dark theme first, light toggle, daisyUI/Tailwind via CDN — no build step. Star repos as favorites (persisted in SQLite); the "★ Fav only" toggle filters the list to starred repos. Search across repo/package/title/CVE, and sort by severity, repo, or alert count. Manage watched repos (add, rename, note, remove) from the "Watched repos" card. Click any repo name (per-repo table, watched list, or alert-group header) to open that repo's dependency report at `/repo/owner/name`: open-alert counts by severity, the alert list with search, recently-fixed alerts, and per-repo sweep history.
- MCP server at `/mcp` (Streamable HTTP, spec 2025-06-18): agents can list/add/update/remove repos, read alerts and summaries, and trigger sweeps with tools `list_repos`, `add_repo`, `update_repo`, `remove_repo`, `get_summary`, `list_alerts`, `trigger_sweep`. The endpoint enforces the spec's Host/Origin checks (DNS-rebinding protection); the bind address is always accepted, extra proxy hostnames go in `MCP_ALLOWED_HOSTS`.

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # add your token and repo list
python run.py               # serves http://127.0.0.1:8000
```

Open http://127.0.0.1:8000. Trigger a sweep from the dashboard or:

```bash
curl -X POST http://127.0.0.1:8000/api/sweep
```

## Configuration (`.env`)

| Key | Meaning | Default |
|-----|---------|---------|
| `GITHUB_TOKEN` | PAT with `repo` (or fine-grained: Dependabot alerts + code scanning read) | required |
| `REPOS` | comma-separated `owner/name` list, imported into the DB on first run (the DB is the source of truth afterwards) | empty |
| `GITHUB_API_BASE` | API base URL (GHES support) | `https://api.github.com` |
| `SWEEP_TIMES` | 24h local times, comma-separated | `09:30,15:30,17:30` |
| `DB_PATH` | SQLite file | `repo_watcher.db` |
| `HOST` / `PORT` | bind address | `127.0.0.1` / `8000` |

`.env` is gitignored — never commit tokens or private repo names.

## API

| Route | Purpose |
|-------|---------|
| `GET /` | dashboard |
| `GET /repo/{owner}/{name}` | one repo's dependency report — 404 if not watched |
| `GET /api/summary` | counts by severity/source, new & fixed since previous sweep |
| `GET /api/alerts` | open alerts from the latest sweep |
| `GET /api/sweeps` | sweep history |
| `POST /api/sweep` | run a sweep now |
| `POST /api/favorite` | star/unstar a repo (`{"repo": "...", "on": true}`) |
| `GET /api/repos` | watched repos (`name`, `added_at`, `note`) |
| `POST /api/repos` | watch a repo (`{"name": "owner/repo", "note": ""}`) — 400 invalid, 409 duplicate |
| `PATCH /api/repos` | rename/note (`{"name": "...", "new_name": "...", "note": "..."}`) — rename cascades to alert history |
| `DELETE /api/repos?name=…` | stop watching — 404 unknown; alert history is kept |
| `POST /mcp` | MCP Streamable HTTP endpoint (tools listed above) |

## Layout

```
app/
  config.py      .env loading + validation
  github_api.py  Dependabot / code-scanning fetchers
  store.py       SQLite schema + queries
  sweeper.py     one sweep: fetch -> store -> diff
  main.py        FastAPI app, scheduler, dashboard, MCP mount
  mcp_server.py  FastMCP tools over the same Store
  templates/     dashboard.html, report.html, _head.html (shared head/styles)
run.py           entry point
```

## Notes

- A repo that returns 404 is reported as inaccessible, never guessed.
- `first_patched_version` may be null → shown as `unavailable` (no fix release yet).
- This tool is read-only against GitHub: it never opens PRs, fixes, or dismisses alerts.
