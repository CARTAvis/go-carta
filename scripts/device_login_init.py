#!/usr/bin/env python3
"""Start a CARTA device login: generate an Ed25519 keypair and register the public key.

Requires: pip install cryptography requests
"""
import argparse
import base64
import hashlib
import json
import os
import sys

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", default="http://localhost:8081", help="Base URL of carta-ctl")
    parser.add_argument("--key-file", default="carta_device_key.pem", help="Where to write the private key")
    parser.add_argument("--state-file", default="carta_device_login.json", help="Where to write the login state")
    args = parser.parse_args()

    private_key = Ed25519PrivateKey.generate()
    public_raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

    fingerprint = b64url(hashlib.sha256(public_raw).digest())

    resp = requests.post(
        args.server.rstrip("/") + "/api/auth/device_init",
        json={"public_key": b64url(public_raw)},
        timeout=10,
    )
    if resp.status_code != 200:
        print(f"device_init failed: {resp.status_code} {resp.text}", file=sys.stderr)
        return 1
    data = resp.json()
    if data["key_fingerprint"] != fingerprint:
        print("Server fingerprint does not match the local key; aborting.", file=sys.stderr)
        return 1

    # Only write the private key once the server has accepted the registration.
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd = os.open(args.key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)

    fd = os.open(args.state_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"key_fingerprint": fingerprint, "interval": data["interval"]}, f)

    print(f"Confirmation code: {fingerprint[:8]}")
    print("Check that this matches the code shown on the sign-in page.")
    print(f"Open this URL in a browser to sign in:\n  {data['verification_uri']}")
    print(f"Expires in {data['expires_in']}s. Private key saved to {args.key_file}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
