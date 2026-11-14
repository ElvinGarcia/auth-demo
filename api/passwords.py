"""Password hashing used by Level 1 and every level after it.

PBKDF2-HMAC-SHA256 from the standard library: salted, deliberately slow,
and the parameters are stored with the hash so they can be raised later.
"""
import hashlib
import hmac
import os
import secrets

# OWASP's 2023 guidance for PBKDF2-HMAC-SHA256 is 600,000 iterations.
# Override with PBKDF2_ITERATIONS (tests lower it so they run fast; a
# Cloudflare Worker's CPU limit may force a lower value, so measure there).
DEFAULT_ITERATIONS = 600_000
SCHEME = "pbkdf2_sha256"


def _iterations() -> int:
    return int(os.environ.get("PBKDF2_ITERATIONS", DEFAULT_ITERATIONS))


def hash_password(password: str, iterations: int | None = None) -> str:
    iterations = iterations or _iterations()
    salt = secrets.token_bytes(16)  # unique per password: equal passwords, different hashes
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"{SCHEME}${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations, salt_hex, digest_hex = stored.split("$")
        if scheme != SCHEME:
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations)
        )
        # Constant-time comparison, so response timing leaks nothing about the hash.
        return hmac.compare_digest(digest, bytes.fromhex(digest_hex))
    except ValueError:
        return False


# Verified against when a username does not exist, so "unknown user" costs the
# same time as "wrong password" and timing cannot be used to list usernames.
DUMMY_HASH = hash_password("dummy-password-for-timing", iterations=1_000)
