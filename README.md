# Auth Ladder Demo

> **Educational demo.** Level 0 deliberately stores passwords in plaintext and
> no level has rate limiting. **Never enter real passwords**, and don't reuse
> this code in production.

Demonstration project for the 401 Cybersecurity 2 lecture.

It shows **why a username and password alone is weak**, then climbs a ladder of
stronger authentication methods. Each level has its own login flow and an
"attacker view" that demonstrates what a thief can and cannot do once that
method is in place.

## The levels

| Level | Method | Lesson |
|---|---|---|
| 0 | Username + password, stored in plaintext | A breach exposes every password; stolen credentials replay instantly; guessing is unlimited |
| 1 | Hashed passwords | A breach no longer exposes passwords, but weak passwords can still be guessed online and phished |
| 2 | + SMS code | Better than nothing, but codes can be intercepted, SIM-swapped, or relayed by a phishing page |
| 3 | + Email code | Only as strong as the mailbox; still phishable in real time |
| 4 | + TOTP (authenticator app) | Strong against stuffing and interception, but a code can still be relayed within its 30-second window |
| 5 | + FIDO2 / WebAuthn | Challenge-based and origin-bound: replays and lookalike sites fail |

The progression runs from weakest to strongest. Every attacker view uses
simulations and replays against **this demo only**; the repository contains no
tooling for attacking real systems.

## Status

- [x] Project scaffold (FastAPI, SQLite, dev container)
- [x] Level 0: plaintext passwords
- [x] Level 1: hashed passwords
- [ ] Level 2: SMS (mock provider first, real SMS optional)
- [ ] Level 3: email code
- [ ] Level 4: TOTP
- [ ] Level 5: FIDO2 / WebAuthn
- [ ] Deploy to Cloudflare

## Tech stack

- **Backend:** Python 3.12, [FastAPI](https://fastapi.tiangolo.com/), served by uvicorn
- **Database:** SQLite locally (the schema is portable to Cloudflare D1)
- **Frontend:** plain HTML, CSS and JavaScript (no build step)
- **Auth libraries:** [`pyotp`](https://github.com/pyauth/pyotp) (TOTP),
  [`webauthn`](https://github.com/duo-labs/py_webauthn) (FIDO2),
  `qrcode` (TOTP enrollment QR codes)
- **Password hashing:** PBKDF2-HMAC-SHA256 from the Python standard library
- **Tooling:** [uv](https://docs.astral.sh/uv/) for environments and dependencies,
  pytest + httpx for tests
- **Planned hosting:** Cloudflare Workers (Python) + D1

## Run it locally

Pick one option. Always open the site at **`http://localhost:8000`**, not
`127.0.0.1`: WebAuthn (Level 5) needs a real hostname, and browsers treat
`localhost` as a secure context.

### Option A: dev container (recommended for development)

Requires Docker and VS Code with the *Dev Containers* extension. The config in
`.devcontainer/` uses a locally built image named `dev-env`; if you don't have
it, use option B or C.

1. Clone the repo and open the folder in VS Code.
2. Run **Dev Containers: Reopen in Container** from the command palette.
   The post-create script installs uv (if missing) and runs `uv sync`.
3. In the container terminal, start the server:

   ```sh
   uv run uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
   ```

### Option B: Docker Compose

Requires Docker only.

```sh
docker compose up --build
```

The database lives in a Docker volume and survives restarts. Reset it with:

```sh
docker compose down -v
```

### Option C: your own machine

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/getting-started/installation/).

```sh
git clone https://github.com/ElvinGarcia/auth-demo.git
cd auth-demo
uv sync
uv run uvicorn api.main:app --reload
```

### Useful URLs

| URL | What it is |
|---|---|
| <http://localhost:8000> | The demo site (landing page with every level) |
| <http://localhost:8000/level0/> | Level 0 login |
| <http://localhost:8000/level1/> | Level 1 login |
| <http://localhost:8000/api/health> | Health check (`{"status": "ok"}`) |
| <http://localhost:8000/docs> | Interactive API docs (Swagger UI) |

Each level also has an attacker view, for example `/level0/attacker.html` and
`/level1/attacker.html`.

## How the demo accounts work

There is no registration. The **first login with a new username creates the
account**, using whatever password you typed; later logins must match it.
Four weak seeded accounts exist at every level so the attacker views have
something to attack: `admin`, `alice`, `bob` and `carol`.

## Attacker scripts

The guessing script runs against your own demo and refuses non-local hosts
unless you pass `--allow-remote` (only for a deployment you own).

```sh
# Online guessing against the seeded accounts, with a small wordlist
uv run python scripts/bruteforce.py --level 0
uv run python scripts/bruteforce.py --level 1

# One account only
uv run python scripts/bruteforce.py --level 1 --users admin
```

Compare the guesses-per-second figure at the two levels: hashing makes each
guess more expensive, but nothing stops the guessing.

## Common commands

```sh
uv run uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload   # run with auto-reload
uv run pytest -q                                                    # run the tests
uv add <package>                                                    # add a dependency
uv add --dev <package>                                              # add a dev-only dependency
uv sync                                                             # reinstall from the lockfile
rm demo.db                                                          # reset the local database
```

`demo.db` is recreated from `schema.sql` on the next start. Tests use a
temporary database and never touch it.

## Project structure

```
auth-demo/
├── .devcontainer/           # Dev container config and post-create script
├── api/
│   ├── main.py              # FastAPI app; serves /api/* and the static site
│   ├── db.py                # SQLite connection and schema init
│   ├── sessions.py          # Session tokens and cookies, shared by all levels
│   ├── passwords.py         # PBKDF2 hashing (Level 1 onwards)
│   ├── auth/                # One module per level, plus its attacker view
│   └── providers/           # SMS / email providers (mock and real), added later
├── web/
│   ├── index.html           # Landing page
│   ├── shared/              # Common CSS and JS
│   └── level0/, level1/ ... # Login pages and attacker views
├── scripts/                 # Guessing script and wordlist
├── tests/                   # pytest suite
├── schema.sql               # Database schema
├── Dockerfile, docker-compose.yml
├── pyproject.toml, uv.lock
└── README.md
```

## Running safely

- Use **synthetic accounts and fake passwords only**, especially at Level 0.
- `demo.db` is gitignored. Don't commit it.
- Secrets (email/SMS provider keys, Cloudflare tokens) go in a `.env` file,
  which is gitignored. Never commit it.
- SMS is mocked by default, so the demo can't send real texts or run up costs.
- The attacker views can be switched off on a deployment with `ATTACKER_VIEW=0`.

## Roadmap notes

- **Deployment:** Python Workers on Cloudflare serving the static pages and the
  API from one Worker, with D1 for storage. Free-tier CPU limits mean the
  password-hashing iteration count will need testing there.
- **Email:** console output locally, then a transactional email provider
  (domain verified with SPF/DKIM) for the hosted version.
- **Stretch goals:** real SMS through a provider, a lookalike-hostname demo for
  WebAuthn origin binding, and a nightly reset of demo data.

## Authors

- [Elvin Garcia](https://github.com/ElvinGarcia)
- [JuanMatos1](https://github.com/JuanMatos1)

## License

TBD. Choose one (for example MIT) before relying on this beyond the class.
