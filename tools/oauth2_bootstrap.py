#!/usr/bin/env python3
"""PKCE bootstrap for the X MCP server.

Run this once on your host (not in Docker — needs a browser). It:
  1. Reads X_OAUTH2_CLIENT_ID / X_OAUTH2_REDIRECT_URI / X_OAUTH2_SCOPES from .env
  2. Generates a PKCE verifier + challenge
  3. Opens your browser to X's authorization URL
  4. Listens on the redirect_uri for the auth code
  5. Exchanges the code for access_token + refresh_token
  6. Writes the tokens back into .env AND data/tokens.json

After that, the server can refresh indefinitely without browser involvement.

Usage:
    cd /Users/chen/Projects/xmcp
    .venv/bin/python tools/oauth2_bootstrap.py
"""
from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import secrets
import socketserver
import sys
import threading
import time
import urllib.parse
import webbrowser
from pathlib import Path

try:
    import httpx
except ImportError:
    sys.stderr.write("ERROR: httpx not installed. Activate .venv first.\n")
    sys.exit(1)

ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = ROOT / ".env"
TOKENS_PATH = ROOT / "data" / "tokens.json"

AUTHORIZE_URL = "https://x.com/i/oauth2/authorize"
TOKEN_URL = "https://api.x.com/2/oauth2/token"


def load_env() -> dict[str, str]:
    env: dict[str, str] = {}
    if not ENV_PATH.exists():
        sys.exit(f"No .env at {ENV_PATH}")
    for line in ENV_PATH.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip()
    return env


def write_env_keys(updates: dict[str, str]) -> None:
    """In-place update of matching keys in .env, preserving comments/order.
    For keys not present, append at the end."""
    text = ENV_PATH.read_text()
    lines = text.splitlines()
    seen: set[str] = set()
    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if stripped.startswith("#") or "=" not in stripped:
            continue
        k = stripped.split("=", 1)[0].strip()
        if k in updates:
            lines[i] = f"{k}={updates[k]}"
            seen.add(k)
    for k, v in updates.items():
        if k not in seen:
            lines.append(f"{k}={v}")
    ENV_PATH.write_text("\n".join(lines) + "\n")


def pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def start_callback_server(redirect_uri: str) -> tuple[threading.Thread, dict, socketserver.TCPServer]:
    parsed = urllib.parse.urlparse(redirect_uri)
    host = parsed.hostname or "localhost"
    port = parsed.port or 80
    path = parsed.path or "/"
    result: dict[str, str | None] = {"code": None, "state": None, "error": None}
    event = threading.Event()

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):  # silence default logging
            pass

        def do_GET(self):  # noqa: N802
            u = urllib.parse.urlparse(self.path)
            if u.path != path:
                self.send_response(404)
                self.end_headers()
                return
            q = urllib.parse.parse_qs(u.query)
            result["code"] = (q.get("code") or [None])[0]
            result["state"] = (q.get("state") or [None])[0]
            result["error"] = (q.get("error_description") or q.get("error") or [None])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            if result["error"]:
                self.wfile.write(f"<h1>Error</h1><pre>{result['error']}</pre>".encode())
            else:
                self.wfile.write(b"<h1>Authorized.</h1><p>You can close this tab and return to the terminal.</p>")
            event.set()

    class ReusableTCPServer(socketserver.TCPServer):
        allow_reuse_address = True

    server = ReusableTCPServer((host, port), Handler)

    def run():
        while not event.is_set():
            server.handle_request()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t, result, server


def main() -> int:
    env = load_env()
    client_id = env.get("X_OAUTH2_CLIENT_ID", "")
    client_secret = env.get("X_OAUTH2_CLIENT_SECRET", "")
    redirect_uri = env.get("X_OAUTH2_REDIRECT_URI", "http://localhost:3000/callback")
    scopes = env.get("X_OAUTH2_SCOPES", "tweet.read users.read bookmark.read like.read follows.read offline.access")

    if not client_id:
        sys.exit("X_OAUTH2_CLIENT_ID is missing from .env")

    verifier, challenge = pkce_pair()
    state = secrets.token_urlsafe(24)

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scopes,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    auth_url = f"{AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"

    print(f"[xmcp-oauth2] redirect_uri = {redirect_uri}")
    print(f"[xmcp-oauth2] scopes       = {scopes}")
    print(f"[xmcp-oauth2] starting local callback listener…")
    _, result, server = start_callback_server(redirect_uri)

    print(f"[xmcp-oauth2] opening browser to:\n  {auth_url}\n")
    webbrowser.open(auth_url)

    # Wait up to 5 minutes for the user to complete the flow.
    deadline = time.time() + 300
    while time.time() < deadline and result["code"] is None and result["error"] is None:
        time.sleep(0.25)
    server.server_close()

    if result["error"]:
        sys.exit(f"[xmcp-oauth2] authorization denied: {result['error']}")
    if not result["code"]:
        sys.exit("[xmcp-oauth2] timed out waiting for callback")
    if result["state"] != state:
        sys.exit("[xmcp-oauth2] state mismatch — possible CSRF. Aborting.")

    print("[xmcp-oauth2] got authorization code, exchanging for tokens…")

    data = {
        "grant_type": "authorization_code",
        "code": result["code"],
        "redirect_uri": redirect_uri,
        "code_verifier": verifier,
        "client_id": client_id,
    }
    auth = (client_id, client_secret) if client_secret else None
    resp = httpx.post(TOKEN_URL, data=data, auth=auth, timeout=30)
    if resp.status_code != 200:
        sys.exit(f"[xmcp-oauth2] token exchange failed: HTTP {resp.status_code}\n{resp.text[:600]}")

    body = resp.json()
    access_token = body.get("access_token")
    refresh_token = body.get("refresh_token")
    expires_in = body.get("expires_in", 7200)
    if not access_token or not refresh_token:
        sys.exit(f"[xmcp-oauth2] missing tokens in response: keys = {list(body.keys())}")

    # Persist to .env
    write_env_keys({
        "X_OAUTH2_ACCESS_TOKEN": access_token,
        "X_OAUTH2_REFRESH_TOKEN": refresh_token,
    })

    # Persist to tokens.json (source of truth after first run)
    TOKENS_PATH.parent.mkdir(parents=True, exist_ok=True)
    TOKENS_PATH.write_text(json.dumps({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_at": time.time() + expires_in,
        "obtained_at": time.time(),
        "scopes": scopes,
    }, indent=2))
    os.chmod(TOKENS_PATH, 0o600)

    print(f"[xmcp-oauth2] tokens written to .env and {TOKENS_PATH}")
    print(f"[xmcp-oauth2] access_token expires in ~{expires_in}s; refresh is automatic.")
    print("[xmcp-oauth2] next: docker compose restart xmcp")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
