#!/usr/bin/env python3
"""Log in to a CARTA controller from the command line with a device login.

The script generates an Ed25519 keypair, registers the public key with the
controller, prints the verification URL for the user to approve the device
fingerprint and sign in, then polls /api/auth/device_poll (signing each request
with the private key) until the login is linked. On success a short-lived access
token is saved to the state file. Use --refresh to obtain a new access token
while the key registration is valid, and --revoke to revoke the session on
the controller and delete the local key and state files.

Requires: pip install cryptography requests
"""
import argparse
import base64
import hashlib
import json
import os
import sys
import time

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DEFAULT_SERVER = "http://localhost:8081"
EXPIRY_WARNING_SECONDS = 300

# These must match the messages built by the controller's devicePollMessage,
# deviceRefreshMessage and deviceLogoutMessage.
POLL_MESSAGE_PREFIX = "carta-device-poll"
REFRESH_MESSAGE_PREFIX = "carta-device-refresh"
LOGOUT_MESSAGE_PREFIX = "carta-device-logout"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def write_private_file(path: str, content: bytes) -> None:
    """Write a file that should only be readable by the current user."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(content)


def poll_message(fingerprint: str, timestamp: int) -> bytes:
    """The canonical message the controller expects to be signed on each poll."""
    return f"{POLL_MESSAGE_PREFIX}\n{fingerprint}\n{timestamp}".encode()


def refresh_message(fingerprint: str, timestamp: int) -> bytes:
    """The canonical message the controller expects to be signed on refresh."""
    return f"{REFRESH_MESSAGE_PREFIX}\n{fingerprint}\n{timestamp}".encode()


def logout_message(fingerprint: str, timestamp: int) -> bytes:
    """The canonical message the controller expects to be signed on logout."""
    return f"{LOGOUT_MESSAGE_PREFIX}\n{fingerprint}\n{timestamp}".encode()


def error_message(response: requests.Response) -> str:
    try:
        data = response.json()
    except ValueError:
        return response.text
    return data.get("message") or data.get("error") or response.text


def warn_if_expiring(state) -> None:
    """Warn when the saved session has expired or is close to expiring."""
    expires_at = state.get("session_expires_at")
    if not expires_at:
        return
    try:
        remaining = int(expires_at) - int(time.time())
    except (TypeError, ValueError):
        return

    if remaining <= 0:
        print("Warning: the saved session has expired; log in again.", file=sys.stderr)
    elif remaining <= EXPIRY_WARNING_SECONDS:
        print(f"Warning: the saved session expires in {remaining}s; log in again soon.", file=sys.stderr)


def poll_until_linked(server, fingerprint, private_key, interval, deadline, expires_in):
    """Poll the controller until the login is linked or the deadline passes."""
    last_timestamp = 0
    while time.monotonic() < deadline:
        # Keep the signed timestamp strictly increasing even if the wall clock
        # moves backwards, so the controller never sees a replay.
        timestamp = max(int(time.time()), last_timestamp + 1)
        last_timestamp = timestamp
        signature = b64url(private_key.sign(poll_message(fingerprint, timestamp)))

        try:
            response = requests.post(
                server + "/api/auth/device_poll",
                json={
                    "key_fingerprint": fingerprint,
                    "timestamp": timestamp,
                    "signature": signature,
                },
                timeout=10,
            )
        except requests.exceptions.RequestException as e:
            print(f"Poll request failed ({e}); retrying...", file=sys.stderr)
            time.sleep(interval)
            continue

        if response.status_code == 200:
            try:
                session = response.json()
            except ValueError:
                raise RuntimeError("device_poll returned a success response that was not valid JSON")
            if not all(key in session for key in ("username", "access_token", "expires_in", "session_expires_in")):
                raise RuntimeError("device_poll response is missing session fields")
            return session, last_timestamp

        if response.status_code == 202:
            remaining = int(max(deadline - time.monotonic(), 0))
            print(f"Waiting for confirmation... ({remaining}s left)", file=sys.stderr)
            time.sleep(interval)
            continue

        if response.status_code == 429 or response.status_code >= 500:
            retry_after = response.headers.get("Retry-After")
            wait = int(retry_after) if retry_after and retry_after.isdigit() else interval
            time.sleep(max(wait, 1))
            continue

        raise RuntimeError(f"device_poll failed: {response.status_code} {error_message(response)}")

    raise TimeoutError(f"Timed out after {expires_in}s waiting for the login to be confirmed")


def revoke_session(args) -> int:
    """Revoke the saved device session and delete the local credentials."""
    state_file = os.path.abspath(args.state_file)
    if not os.path.exists(state_file):
        print(f"No saved session found at {state_file}; nothing to revoke.")
        return 0

    try:
        with open(state_file) as f:
            state = json.load(f)
    except (OSError, ValueError) as e:
        print(f"Failed to read {state_file}: {e}", file=sys.stderr)
        return 1

    fingerprint = state.get("key_fingerprint")
    if not fingerprint:
        print(f"No key fingerprint found in {state_file}; cannot revoke.", file=sys.stderr)
        return 1

    key_file = state.get("key_file") or os.path.abspath(args.key_file)
    server = (args.server or state.get("server") or DEFAULT_SERVER).rstrip("/")

    try:
        with open(key_file, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    except (OSError, ValueError) as e:
        print(f"Failed to load private key from {key_file}: {e}", file=sys.stderr)
        return 1

    public_raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    if b64url(hashlib.sha256(public_raw).digest()) != fingerprint:
        print("Local key does not match the saved session; refusing to revoke.", file=sys.stderr)
        return 1

    # The controller rejects timestamps that are not newer than the last
    # accepted signed request, which was the final poll.
    timestamp = max(int(time.time()), int(state.get("last_request_ts", 0)) + 1)
    signature = b64url(private_key.sign(logout_message(fingerprint, timestamp)))

    try:
        response = requests.post(
            server + "/api/auth/device_logout",
            json={
                "key_fingerprint": fingerprint,
                "timestamp": timestamp,
                "signature": signature,
            },
            timeout=10,
        )
    except requests.exceptions.RequestException as e:
        print(f"device_logout failed: {e}", file=sys.stderr)
        return 1

    # 410 means the controller no longer knows the session (already revoked or
    # expired), which is still the desired end state.
    if response.status_code not in (200, 410):
        print(f"device_logout failed: {response.status_code} {error_message(response)}", file=sys.stderr)
        return 1

    for path in (state_file, key_file):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        except OSError as e:
            print(f"Warning: could not remove {path}: {e}", file=sys.stderr)

    print("Device session revoked; local credentials removed.")
    return 0


def refresh_session(args) -> int:
    """Refresh the saved access token using the registered device key."""
    state_file = os.path.abspath(args.state_file)
    if not os.path.exists(state_file):
        print(f"No saved session found at {state_file}; log in first.", file=sys.stderr)
        return 1

    try:
        with open(state_file) as f:
            state = json.load(f)
    except (OSError, ValueError) as e:
        print(f"Failed to read {state_file}: {e}", file=sys.stderr)
        return 1

    warn_if_expiring(state)

    fingerprint = state.get("key_fingerprint")
    if not fingerprint:
        print(f"No key fingerprint found in {state_file}; log in again.", file=sys.stderr)
        return 1

    key_file = state.get("key_file") or os.path.abspath(args.key_file)
    server = (args.server or state.get("server") or DEFAULT_SERVER).rstrip("/")

    try:
        with open(key_file, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    except (OSError, ValueError) as e:
        print(f"Failed to load private key from {key_file}: {e}", file=sys.stderr)
        return 1

    public_raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    if b64url(hashlib.sha256(public_raw).digest()) != fingerprint:
        print("Local key does not match the saved session; log in again.", file=sys.stderr)
        return 1

    timestamp = max(int(time.time()), int(state.get("last_request_ts", 0)) + 1)
    response = None
    for attempt in range(2):
        signature = b64url(private_key.sign(refresh_message(fingerprint, timestamp)))
        try:
            response = requests.post(
                server + "/api/auth/device_refresh",
                json={
                    "key_fingerprint": fingerprint,
                    "timestamp": timestamp,
                    "signature": signature,
                },
                timeout=10,
            )
        except requests.exceptions.RequestException as e:
            print(f"device_refresh failed: {e}", file=sys.stderr)
            return 1

        # A lost response may have advanced the controller's timestamp; retry
        # once with a newer one before giving up.
        if response.status_code == 409 and attempt == 0:
            timestamp += 1
            continue
        break

    if response.status_code in (401, 410):
        print("Session expired or revoked; run the login flow again.", file=sys.stderr)
        return 1
    if response.status_code != 200:
        print(f"device_refresh failed: {response.status_code} {error_message(response)}", file=sys.stderr)
        return 1

    try:
        refreshed = response.json()
    except ValueError:
        print("device_refresh returned a success response that was not valid JSON.", file=sys.stderr)
        return 1
    if "access_token" not in refreshed:
        print("device_refresh response is missing the access token.", file=sys.stderr)
        return 1

    now = int(time.time())
    state.update(
        {
            "username": refreshed.get("username", state.get("username")),
            "access_token": refreshed["access_token"],
            "expires_in": refreshed.get("expires_in"),
            "access_token_expires_at": now + int(refreshed.get("expires_in", 0)),
            "session_expires_in": refreshed.get("session_expires_in"),
            "session_expires_at": now + int(refreshed.get("session_expires_in", 0)),
            "last_request_ts": timestamp,
        }
    )
    write_private_file(state_file, json.dumps(state, indent=2).encode())

    remaining = int(refreshed.get("session_expires_in") or 0)
    print(f"Access token refreshed; session expires in {remaining}s.")
    if remaining <= EXPIRY_WARNING_SECONDS:
        print(f"Warning: the session expires in {remaining}s; log in again soon.", file=sys.stderr)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", default=None, help=f"Base URL of carta-ctl (default: {DEFAULT_SERVER})")
    parser.add_argument("--key-file", default="carta_device_key.pem", help="Where to write the private key")
    parser.add_argument("--state-file", default="carta_device_login.json", help="Where to write the login state")
    parser.add_argument("--timeout", type=float, default=600.0, help="Maximum seconds to wait for confirmation")
    parser.add_argument("--revoke", action="store_true", help="Revoke the saved device session and remove local credentials")
    parser.add_argument("--refresh", action="store_true", help="Refresh the saved access token using the device key")
    args = parser.parse_args()

    if args.revoke:
        return revoke_session(args)
    if args.refresh:
        return refresh_session(args)

    server = (args.server or DEFAULT_SERVER).rstrip("/")
    key_file = os.path.abspath(args.key_file)
    state_file = os.path.abspath(args.state_file)

    private_key = Ed25519PrivateKey.generate()
    public_raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    fingerprint = b64url(hashlib.sha256(public_raw).digest())

    try:
        response = requests.post(
            server + "/api/auth/device_init",
            json={"public_key": b64url(public_raw)},
            timeout=10,
        )
    except requests.exceptions.RequestException as e:
        print(f"device_init failed: {e}", file=sys.stderr)
        return 1

    if response.status_code != 200:
        print(f"device_init failed: {response.status_code} {error_message(response)}", file=sys.stderr)
        return 1

    data = response.json()
    if data["key_fingerprint"] != fingerprint:
        print("Server fingerprint does not match the local key; aborting.", file=sys.stderr)
        return 1

    # Only write the private key once the server has accepted the registration.
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    write_private_file(key_file, pem)

    interval = max(int(data.get("interval", 5)), 1)
    expires_in = int(data.get("expires_in", args.timeout))
    verification_uri = data["verification_uri"]

    state = {
        "server": server,
        "key_fingerprint": fingerprint,
        "key_file": key_file,
        "interval": interval,
        "verification_uri": verification_uri,
    }
    write_private_file(state_file, json.dumps(state, indent=2).encode())

    print(f"Confirmation code: {fingerprint[:8]}")
    print("Open this URL in a browser, check that the fingerprint matches,")
    print("approve it, and then sign in:")
    print(f"  {verification_uri}")
    print("Waiting for the login to be confirmed...")

    deadline = time.monotonic() + min(args.timeout, expires_in)

    try:
        session, last_signed = poll_until_linked(server, fingerprint, private_key, interval, deadline, expires_in)
    except (TimeoutError, RuntimeError) as e:
        print(f"Login failed: {e}", file=sys.stderr)
        return 1

    now = int(time.time())
    state.update(
        {
            "username": session["username"],
            "access_token": session["access_token"],
            "expires_in": session.get("expires_in"),
            "access_token_expires_at": now + int(session.get("expires_in", 0)),
            "session_expires_in": session.get("session_expires_in"),
            "session_expires_at": now + int(session.get("session_expires_in", 0)),
            "last_request_ts": last_signed,
        }
    )
    write_private_file(state_file, json.dumps(state, indent=2).encode())

    print(
        f"Logged in as {session['username']} "
        f"(access token valid for {session.get('expires_in')}s, "
        f"session for {session['session_expires_in']}s)."
    )
    print(f"Session saved to {state_file}; private key saved to {key_file}.")
    print("Use --refresh to renew the access token, or --revoke to log out.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
