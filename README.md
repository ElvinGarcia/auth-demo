
# Auth Ladder Demo

> **Educational demo.** Level 0 deliberately stores passwords in plaintext and
> no level has rate limiting on password guesses. **Never enter real passwords**,
> and don't reuse this code in production.

Demonstration project for the 401 Cybersecurity 2 lecture.

It shows **why a username and password alone is weak**, then climbs a ladder of
stronger authentication methods. Each level has its own login flow and an
"attacker view" that demonstrates what a thief can and cannot do once that
method is in place.

## The levels

| Level | Method | What finally beats it |
|---|---|---|
| 0 | Username + password, stored in plaintext | Read the database, or guess |
| 1 | Hashed passwords | Guess online, reuse stolen passwords, phish |
| 2 | + SMS code | SIM swap, or relay the code through a fake page |
| 3 | + Email code | Take over the mailbox, or relay the code |
| 4 | + TOTP (authenticator app) | Leak the stored secret, or relay the code in real time |
| 5 | + FIDO2 / WebAuthn | Steal the session after login, or abuse a weaker recovery path |

The progression runs from weakest to strongest. Every attacker view uses
simulations and replays against **this demo only**; the repository contains no
tooling for attacking real systems, and no fake login pages.

## Status

- [x] Project scaffold (FastAPI, SQLite, dev container)
- [x] Level 0: plaintext passwords
- [x] Level 1: hashed passwords
- [x] Level 2: SMS code (mock carrier; real SMS optional later)
- [x] Level 3: email code (mock mail system)
- [x] Level 4: TOTP
- [x] Level 5: FIDO2 / WebAuthn
- [ ] Deploy to Cloudflare
## Tech stack

- **Backend:** Python 3.12, [FastAPI](https://fastapi.tiangolo.com/), served by uvicorn
- **Database:** SQLite locally (the schema is portable to Cloudflare D1)
- **Frontend:** plain HTML, CSS and JavaScript (no build step)
- **Auth libraries:** [`pyotp`](https://github.com/pyauth/pyotp) (TOTP),
  [`webauthn`](https://github.com/duo-labs/py_webauthn) (FIDO2),
  `qrcode` (TOTP enrollment QR codes), `cryptography` and `cbor2`
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
| <http://localhost:8000> | Landing page with every level |
| <http://localhost:8000/level0/> ... `/level5/` | The login page for each level |
| <http://localhost:8000/level0/attacker.html> ... `/level5/attacker.html` | The attacker view for each level |
| <http://localhost:8000/api/health> | Health check (`{"status": "ok"}`) |
| <http://localhost:8000/docs> | Interactive API docs (Swagger UI) |

## How the demo accounts work

There is no registration. The **first login with a new username creates the
account** at that level, using whatever password you typed; later logins must
match it. The same username can exist at several levels as separate accounts.

Four weak seeded accounts exist at every level so the attacker views have
something to attack: `admin`, `alice`, `bob` and `carol`. Attacker views only
ever show the seeded accounts plus **your own**, never other visitors'.

## Trying each level

| Level | What to do |
|---|---|
| 0, 1 | Log in as a new user, then open the attacker view: the dump, the replay, and the guessing script below |
| 2 | Log in, read the code in the simulated phone panel. In the attacker view, "SIM swap" admin's number and log in as admin |
| 3 | Log in, read the code in the simulated mailbox. In the attacker view, open admin's mailbox with the reused password |
| 4 | Scan the QR code with an authenticator app (or use the built-in demo one). In the attacker view, read the leaked secrets and compute admin's codes |
| 5 | Register a passkey or security key (Touch ID works on a Mac). In the attacker view, try the leaked table, a made-up response, and a replay |

For Level 5, open the site as exactly `http://localhost:8000`. If the page shows
a red address warning, set the `WEBAUTHN_*` variables below.

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

## Configuration

All settings are optional environment variables.

| Variable | Default | Purpose |
|---|---|---|
| `AUTH_DEMO_DB` | `demo.db` in the project root | SQLite file location |
| `PBKDF2_ITERATIONS` | `600000` | Password-hashing cost. Lower it for slow machines in development; keep the default for anything you show |
| `ATTACKER_VIEW` | `1` | Set to `0` to switch off the attacker-view endpoints |
| `COOKIE_SECURE` | `0` | Set to `1` when serving over HTTPS |
| `SMS_CODE_KEY` / `EMAIL_CODE_KEY` | dev-only values | Keys for the stored hashes of one-time codes. **Set real values on any deployment** |
| `WEBAUTHN_RP_ID` | `localhost` | Site name passkeys are bound to. Use your domain when deployed |
| `WEBAUTHN_ORIGINS` | `http://localhost:8000` | Comma-separated origins the server accepts for WebAuthn |

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

## Tests

The suite covers every level, including the attack scenarios: replayed codes,
expired codes, lockouts, SIM-swap and mailbox takeover, leaked secrets, and
WebAuthn replay, wrong-site and cloned-key cases. Level 5 is tested with a
software authenticator (`tests/softkey.py`) that builds real WebAuthn messages,
so the server's verification code runs for real.

```sh
uv run pytest -q
```

## Project structure

```
auth-demo/
├── .devcontainer/           # Dev container config and post-create script
├── api/
│   ├── main.py              # FastAPI app; serves /api/* and the static site
│   ├── db.py                # SQLite connection and schema init
│   ├── sessions.py          # Session tokens and cookies, shared by all levels
│   ├── passwords.py         # PBKDF2 hashing (Level 1 onwards)
│   ├── auth/                # level0.py ... level5.py, each with a *_attacker.py
│   └── providers/           # Mock SMS and email providers (swap for real ones later)
├── web/
│   ├── index.html           # Landing page
│   ├── shared/              # Common CSS and JS
│   └── level0/ ... level5/  # Login pages and attacker views
├── scripts/                 # Guessing script and wordlist
├── tests/                   # pytest suite and the software authenticator
├── schema.sql               # Database schema
├── Dockerfile, docker-compose.yml
├── pyproject.toml, uv.lock
└── README.md
```

## Working on it

Each level was built on its own branch (`level-N-...`), merged to `main`, and
tagged `level-N`, so any stage can be checked out on its own:

```sh
git checkout level-3
```

## Running safely

- Use **synthetic accounts and fake passwords only**, especially at Level 0.
- `demo.db` is gitignored. Don't commit it.
- Secrets (email/SMS provider keys, Cloudflare tokens, code-hashing keys) go in
  a `.env` file, which is gitignored. Never commit it.
- SMS and email are mocked, so the demo can't text or email a real person.
  Every demo address ends in `.invalid`, which can never receive mail.
- The TOTP table stores secrets in plaintext on purpose, to show what a leak
  means for a shared-secret factor. A real service should encrypt them at rest.
## Roadmap

- **Deployment:** Python Workers on Cloudflare serving the static pages and the
  API from one Worker, with D1 for storage. Open questions: whether the
  `webauthn` package and its native dependencies run on Pyodide, and whether
  the password-hashing cost fits the free-tier CPU limit.
- **Real providers:** a transactional email service (domain verified with
  SPF/DKIM) and, optionally, real SMS.
- **Cleanup:** the one-time-code levels (2 and 3) and the pending-login logic
  (levels 2 to 5) share a lot of code and could be factored into one module.
- **Stretch goals:** a nightly reset of demo data, and a look-alike-hostname
  demo for WebAuthn origin binding.
## Authors

- [Elvin Garcia](https://github.com/ElvinGarcia)
- [JuanMatos1](https://github.com/JuanMatos1)
- [CyberDrewX](https://github.com/CyberDrewX)
## License



