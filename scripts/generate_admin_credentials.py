#!/usr/bin/env python3
"""Generate the deployment credentials this platform needs.

Produces values you paste ONCE into the Gcore Secrets Manager during
deployment (see docs/DEPLOYMENT.md). Uses only the Python standard
library, mirrors the exact hash format the Rust code verifies
(pbkdf2-sha256$iterations$salt_b64$hash_b64).

Usage:
  python3 scripts/generate_admin_credentials.py --password 'a-long-password'
  python3 scripts/generate_admin_credentials.py --all          # all values
  python3 scripts/generate_admin_credentials.py --session-key   # signing key only

The printed hash format matches:
  pbkdf2-sha256$<iterations>$<salt_b64>$<hash_b64>
Verification honors the parameters embedded in the hash; the platform
enforces a 10,000-iteration security floor.
"""
import argparse
import base64
import hashlib
import os
import sys

DEFAULT_ITERATIONS = 100_000


def make_hash(password: str, iterations: int = DEFAULT_ITERATIONS) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, dklen=32)
    return "$".join([
        "pbkdf2-sha256",
        str(iterations),
        base64.b64encode(salt).decode(),
        base64.b64encode(dk).decode(),
    ])


def make_key() -> str:
    return base64.b64encode(os.urandom(32)).decode()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--password", help="Admin password to hash")
    ap.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS)
    ap.add_argument("--all", action="store_true", help="Print every deployment value")
    ap.add_argument("--session-key", action="store_true", help="Print only a session signing key")
    args = ap.parse_args()

    if args.all or args.session_key:
        print(f"SESSION_SIGNING_KEY={make_key()}")
        print(f"APP_TOKEN_SIGNING_KEY={make_key()}")
        print(f"GCORE_API_KEY=<paste your Gcore permanent API token here>")
    if args.all or args.password:
        if not args.password:
            sys.exit("--password is required for hashing (or use --all with it)")
        if len(args.password) < 12:
            sys.exit("Password must be at least 12 characters (server-enforced).")
        print(f"ADMIN_USERNAME=bootstrap-admin")
        print(f"ADMIN_PASSWORD_HASH={make_hash(args.password, args.iterations)}")


if __name__ == "__main__":
    main()
