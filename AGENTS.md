# AGENTS.md — repo-watcher

Instructions for AI agents working in this repository. This project is **public**: never commit anything identifying a specific company, organization, or private repository.

## Hard rules

- **No org/repo names in tracked files.** The watch list lives only in `.env` (gitignored). README, AGENTS.md, code, fixtures, and examples use placeholders like `octo-org/web-app`.
- **Never push `.env`, tokens, or real alert data.** `.gitignore` covers `.env` and `*.db`; do not weaken it.
- **Read-only against GitHub.** Do not open PRs, push branches to watched repos, fix dependencies, or dismiss alerts from here. Report findings; humans decide.
- **Source of truth is GitHub's own findings** (Dependabot + code scanning). Do not add local scanners (`npm audit`, `snyk`, …) unless explicitly asked.

## Conventions

- Python 3.12+, stdlib `sqlite3`, FastAPI + Jinja2, `httpx` for GitHub calls. No ORM, no build step for the frontend (daisyUI/Tailwind via CDN).
- Config comes only from `.env` / environment (`app/config.py`). New settings: add to `config.py` **and** `.env.example` **and** the README table.
- GitHub pagination: always `--paginate` equivalent (follow `Link` headers via `httpx` loop). A 404 on a repo = inaccessible; record it, never guess counts.
- Severity values come from the API verbatim (`critical|high|medium|low`). Null `first_patched_version` renders as `unavailable`.

## Sweep model

One sweep = fetch open alerts for every configured repo → insert into `alerts` keyed by `(repo, source, alert_number)` with `last_seen_sweep` → an alert absent from the newest sweep counts as fixed **only if that sweep fetched the same `(repo, source)` cleanly**. A failed fetch must never reconcile: its alerts stay open (visible on the dashboard) so a live vulnerability is never silently hidden. Code-scanning 404 = advanced security not enabled (nothing to reconcile); 403 = permission failure (record, do not reconcile). Keep this invariant; `tests/test_sweeper.py` enforces it.

## Testing / verification

- Run the app (`python run.py`), hit `/api/sweep`, then `/api/summary` and `/api/alerts`; confirm counts match GitHub's UI for one repo.
- UI changes: open the dashboard in a browser, check dark and light themes.
- Before any commit: `grep -ri "<company name>" .` must return nothing in tracked files.

## Design

Minimal iOS-glass: translucent cards, backdrop blur, rounded-2xl, thin borders, dark theme default with a light toggle. Keep it plain; fix ugliness later rather than over-designing now.
