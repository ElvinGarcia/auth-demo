# DEMO PROJECT
## Demonstration project for 401 CyberSecurity 2 Lecture

The purpose of this project is to demostrate the different attack vectors used based on the authentification methods used.

- leve1 0
  - Consist of storing the username and password in plain text in a database
- level 1
  - This level consist of hashing the username and password before storing in a database
- level 2
  - This level involves the use of TOTP as an additional level of security along with the secure storage of the username and password
- level 3
  - This level involves sending a one time generated pin send to the users email.

---
# Auth Ladder Demo

> Level 0 deliberately stores passwords in plaintext
> and has no rate limiting.
>> **Never enter real passwords**

A hands-on project that shows **why a username and password alone is weak**.
Then climbs a ladder of stronger authentication methods.

Each level has its own login flow and an "attacker view" that we will demonstrates what a thief can and cannot do once
that method is in place.

## The levels

| Level | Method | Lesson |
|---|---|---|
| 0 | Username + password | Plaintext storage, breach dumps, brute force, credential stuffing, replay of stolen credentials |
| 1 | + SMS code | Better than nothing, but codes can be intercepted, SIM-swapped, or relayed by a phishing page |
| 2 | + Email code | Only as strong as the mailbox; still phishable in real time |
| 3 | + TOTP (authenticator app) | Strong against stuffing and interception, but a code can still be relayed within its 30-second window |
| 4 | + FIDO2 / WebAuthn | Challenge-based and origin-bound: replays and lookalike sites fail |

The progression is ordered from weakest to strongest. Each attacker panel uses
simulations and replays against **this demo only**; it contains no tooling for
attacking real systems.

## Status

- [x] Project scaffold (FastAPI, SQLite, dev container)
- [x] Level 0: password only (Attacker scripts section pointing at uv run python scripts/bruteforce.py
- [ ] Level 1: SMS (mock provider first, real SMS optional)
- [ ] Level 2: email code
- [ ] Level 3: TOTP
- [ ] Level 4: FIDO2 / WebAuthn
- [ ] Deploy to Cloudflare

## Tech stack

- **Backend:** Python 3.12, [FastAPI](https://fastapi.tiangolo.com/), served by uvicorn
- **Database:** SQLite locally (schema is portable to Cloudflare D1)
- **Frontend:** plain HTML, CSS and JavaScript (no build step)
- **Auth libraries:** [`pyotp`](https://github.com/pyauth/pyotp) (TOTP),
  [`webauthn`](https://github.com/duo-labs/py_webauthn) (FIDO2), `qrcode` (TOTP enrollment QR codes)
- **Tooling:** [uv](https://docs.astral.sh/uv/) for environments and dependencies, pytest + httpx for tests
- **Planned hosting:** Cloudflare Workers (Python) + D1

## Prerequisites

** Currently running on a Dev container (recommended)**

- Docker
- VS Code with the *Dev Containers* extension
- The dev container config uses a locally built image named `dev-env`



### Dev container

1. Clone the repo and open the folder in VS Code.
2. Run **Dev Containers: Reopen in Container** from the command palette.
   The post-create script installs uv (if missing) and runs `uv sync`.
3. In the container terminal, start the server:

   ```sh
   uv run uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
   ```

4. Open <http://localhost:8000> in your browser.


### local machine

```sh
git clone https://github.com/ElvinGarcia/auth-demo.git
cd auth-demo
uv sync
uv run uvicorn api.main:app --reload
```

Then open <http://localhost:8000>.

> Always use `localhost`, not `127.0.0.1`. WebAuthn (Level 4) requires a real
> hostname, and browsers treat `localhost` as a secure context.

### Useful URLs

| URL | What it is |
|---|---|
| <http://localhost:8000> | The demo site |
| <http://localhost:8000/api/health> | Health check (`{"status": "ok"}`) |
| <http://localhost:8000/docs> | Interactive API docs (Swagger UI) |

## Commands used

```sh
# Run the server with auto-reload
uv run uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

# Run the tests
uv run pytest

# Add a dependency
uv add <package>

# Add a dev-only dependency
uv add --dev <package>

# Reinstall everything from the lockfile
uv sync

# Reset the local database (it is recreated from schema.sql on next start)
rm demo.db
```

## Project structure

```
auth-demo/
├── .devcontainer/
│   ├── devcontainer.json    # Dev container config
│   └── post-create.sh       # Installs uv, runs uv sync
├── api/
│   ├── main.py              # FastAPI app, serves /api/* and static files
│   ├── db.py                # SQLite connection + schema init
│   ├── auth/                # One module per level (added as built)
│   └── providers/           # SMS / email providers (mock and real)
├── web/
│   ├── index.html           # Landing page
│   └── level0/ ... level4/  # Login pages and attacker panels (added as built)
├── schema.sql               # Database schema
├── pyproject.toml           # Dependencies
├── uv.lock                  # Pinned dependency versions
└── README.md
```

## Running safely

- Use **synthetic accounts and fake passwords only**, especially at Level 0.
- The local database (`demo.db`) is gitignored. Don't commit it.
- Secrets (API keys for email/SMS providers, Cloudflare tokens) go in a `.env`
  file, which is gitignored. Never commit it.
- SMS is mocked by default so the demo can't send real texts or run up costs.

## Roadmap notes

- **Deployment:** Python Workers on Cloudflare, serving the static pages and the
  API from one Worker, with D1 for storage. Free-tier CPU limits mean password
  hashing parameters will need testing.
- **Email:** console output locally, then a transactional email provider
  (domain verified with SPF/DKIM) for the hosted version.
- **Stretch goals:** real SMS via a provider, a lookalike-hostname demo for
  WebAuthn origin binding, nightly reset of demo data.
