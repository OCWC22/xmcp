"""X API MCP server — OAuth 2.0 User Context (PKCE + refresh).

Architecture:
  - Initial access_token + refresh_token are seeded by tools/oauth2_bootstrap.py
    into .env AND data/tokens.json.
  - On startup the server loads tokens from data/tokens.json (preferred, so that
    rotated refresh tokens survive a container restart) and falls back to .env
    only if the file is absent.
  - On every outbound X API call, an httpx event hook calls
    `TokenStore.get_valid_bearer()`, which refreshes if the current access_token
    is within REFRESH_SKEW_SECONDS of expiry.
  - On a 401 response, the hook invalidates the cached token and the caller
    retries once.
  - Refresh token rotation is persisted back to data/tokens.json.
"""

from __future__ import annotations

import asyncio
import base64
import copy
import json
import logging
import os
import time
from pathlib import Path

import httpx
import requests
from fastmcp import FastMCP

HTTP_METHODS = {
    "get", "post", "put", "patch", "delete", "options", "head", "trace",
}

LOGGER = logging.getLogger("xmcp.x_api")

TOKEN_URL = "https://api.x.com/2/oauth2/token"
REFRESH_SKEW_SECONDS = 60  # refresh when <60s of validity remain
TOKENS_FILE = Path(__file__).resolve().parent / "data" / "tokens.json"


def is_truthy(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def parse_csv_env(key: str) -> set[str]:
    raw = os.getenv(key, "")
    if not raw.strip():
        return set()
    return {item.strip() for item in raw.split(",") if item.strip()}


def load_env() -> None:
    env_path = Path(__file__).resolve().parent / ".env"
    if not env_path.exists():
        return
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv(env_path, override=True)


def setup_logging() -> bool:
    debug_enabled = is_truthy(os.getenv("X_API_DEBUG", "1"))
    level = logging.INFO if debug_enabled else logging.WARNING
    logging.basicConfig(level=level)
    LOGGER.setLevel(level)
    return debug_enabled


# ---------------------------------------------------------------------------
# OAuth2 User Context token management
# ---------------------------------------------------------------------------


class OAuth2TokenStore:
    """Thread/coroutine-safe holder for the X OAuth2 user-context tokens.

    Persists rotated refresh tokens to TOKENS_FILE so container restarts pick
    up the latest values rather than the (possibly revoked) seed from .env.
    """

    def __init__(self, client_id: str, client_secret: str | None) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._expires_at: float = 0.0
        self._lock = asyncio.Lock()
        self._load_from_disk_or_env()

    # --- load/persist ------------------------------------------------------

    def _load_from_disk_or_env(self) -> None:
        if TOKENS_FILE.exists():
            try:
                payload = json.loads(TOKENS_FILE.read_text())
                self._access_token = payload.get("access_token") or None
                self._refresh_token = payload.get("refresh_token") or None
                self._expires_at = float(payload.get("expires_at") or 0.0)
                LOGGER.info("Loaded OAuth2 tokens from %s (expires in %.0fs)",
                            TOKENS_FILE, max(0.0, self._expires_at - time.time()))
                return
            except Exception as exc:
                LOGGER.warning("Could not read %s: %s — falling back to .env", TOKENS_FILE, exc)

        self._access_token = (os.getenv("X_OAUTH2_ACCESS_TOKEN") or "").strip() or None
        self._refresh_token = (os.getenv("X_OAUTH2_REFRESH_TOKEN") or "").strip() or None
        self._expires_at = 0.0  # unknown — force refresh on first use
        if self._access_token:
            LOGGER.info("Loaded OAuth2 tokens from .env (expiry unknown — will refresh on first use)")

    def _persist(self, expires_in: float) -> None:
        self._expires_at = time.time() + expires_in
        TOKENS_FILE.parent.mkdir(parents=True, exist_ok=True)
        TOKENS_FILE.write_text(json.dumps({
            "access_token": self._access_token,
            "refresh_token": self._refresh_token,
            "expires_at": self._expires_at,
            "obtained_at": time.time(),
        }, indent=2))
        try:
            os.chmod(TOKENS_FILE, 0o600)
        except OSError:
            pass

    # --- public API --------------------------------------------------------

    def has_credentials(self) -> bool:
        return bool(self._access_token and self._refresh_token)

    async def get_valid_bearer(self) -> str:
        if not self.has_credentials():
            raise RuntimeError(
                "OAuth2 tokens not present. Run tools/oauth2_bootstrap.py on your "
                "host to complete the PKCE flow, then restart the server."
            )
        # Fast path: token comfortably valid.
        if time.time() < self._expires_at - REFRESH_SKEW_SECONDS:
            return self._access_token  # type: ignore[return-value]
        # Slow path: refresh under the lock so concurrent callers coalesce.
        async with self._lock:
            if time.time() < self._expires_at - REFRESH_SKEW_SECONDS:
                return self._access_token  # type: ignore[return-value]
            await self._refresh()
        return self._access_token  # type: ignore[return-value]

    async def invalidate_and_refresh(self) -> str:
        """Called by the 401-retry path. Forces a refresh regardless of expiry."""
        async with self._lock:
            self._expires_at = 0.0
            await self._refresh()
        return self._access_token  # type: ignore[return-value]

    # --- refresh implementation -------------------------------------------

    async def _refresh(self) -> None:
        assert self._refresh_token is not None
        data = {
            "grant_type": "refresh_token",
            "refresh_token": self._refresh_token,
            "client_id": self._client_id,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        auth = None
        if self._client_secret:
            token = base64.b64encode(
                f"{self._client_id}:{self._client_secret}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {token}"

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(TOKEN_URL, data=data, headers=headers, auth=auth)
        if resp.status_code != 200:
            LOGGER.error("OAuth2 refresh failed: HTTP %s — %s",
                         resp.status_code, resp.text[:400])
            raise RuntimeError(
                f"OAuth2 refresh returned HTTP {resp.status_code}. If this is "
                "invalid_grant, re-run tools/oauth2_bootstrap.py to rebuild tokens."
            )
        body = resp.json()
        new_access = body.get("access_token")
        new_refresh = body.get("refresh_token") or self._refresh_token  # sometimes X rotates, sometimes not
        expires_in = float(body.get("expires_in") or 7200)
        if not new_access:
            raise RuntimeError(f"OAuth2 refresh response missing access_token: {body}")
        self._access_token = new_access
        self._refresh_token = new_refresh
        self._persist(expires_in)
        LOGGER.info("OAuth2 access_token refreshed (expires in %.0fs)", expires_in)


# ---------------------------------------------------------------------------
# OpenAPI loading + filtering + schema slimming (unchanged semantics)
# ---------------------------------------------------------------------------


def should_join_query_param(param: dict) -> bool:
    if param.get("in") != "query":
        return False
    schema = param.get("schema", {})
    if schema.get("type") != "array":
        return False
    return param.get("explode") is False


def _truncate_text(value: str | None, limit: int) -> str | None:
    if not isinstance(value, str):
        return value
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def _slim_schema_tree(schema: dict) -> None:
    if not isinstance(schema, dict):
        return
    for heavy in ("example", "examples", "externalDocs", "x-twitter-enum-descriptions"):
        schema.pop(heavy, None)
    desc = schema.get("description")
    trimmed = _truncate_text(desc, 140)
    if trimmed is not None:
        schema["description"] = trimmed
    elif "description" in schema:
        schema.pop("description", None)
    for inner in ("properties", "patternProperties"):
        child = schema.get(inner)
        if isinstance(child, dict):
            for v in child.values():
                _slim_schema_tree(v)
    for inner in ("items", "additionalProperties", "not"):
        child = schema.get(inner)
        if isinstance(child, dict):
            _slim_schema_tree(child)
    for inner in ("allOf", "anyOf", "oneOf"):
        arr = schema.get(inner)
        if isinstance(arr, list):
            for v in arr:
                _slim_schema_tree(v)


def _slim_parameter(param: dict, comma_params: set[str]) -> None:
    if not isinstance(param, dict) or "$ref" in param:
        return
    name = param.get("name")
    schema = param.get("schema")
    if not isinstance(schema, dict):
        return
    is_comma_array = (
        schema.get("type") == "array" and param.get("explode") is False
    ) or name in comma_params
    if is_comma_array:
        items = schema.get("items") if isinstance(schema.get("items"), dict) else {}
        enum_vals = items.get("enum") or []
        sample = ",".join(list(enum_vals)[:4]) if enum_vals else ""
        hint_parts = ["Comma-separated list"]
        if sample:
            hint_parts.append(f"(e.g. {sample})")
        param["schema"] = {"type": "string", "description": " ".join(hint_parts)}
    else:
        _slim_schema_tree(schema)
    if "description" in param:
        param["description"] = _truncate_text(param["description"], 140)
        if not param["description"]:
            param.pop("description", None)


def slim_openapi_spec(spec: dict, comma_params: set[str]) -> None:
    for param in spec.get("components", {}).get("parameters", {}).values():
        _slim_parameter(param, comma_params)
    schemas = spec.get("components", {}).get("schemas", {})
    for schema in schemas.values():
        _slim_schema_tree(schema)
    for path, item in spec.get("paths", {}).items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(op, dict):
                continue
            for p in op.get("parameters", []) or []:
                _slim_parameter(p, comma_params)
            if "summary" in op:
                op["summary"] = _truncate_text(op["summary"], 140)
            if "description" in op:
                op["description"] = _truncate_text(op["description"], 240)
            op.pop("externalDocs", None)
            body = op.get("requestBody")
            if isinstance(body, dict):
                for content in (body.get("content") or {}).values():
                    if isinstance(content, dict) and isinstance(content.get("schema"), dict):
                        _slim_schema_tree(content["schema"])


def collect_comma_params(spec: dict) -> set[str]:
    comma_params: set[str] = set()
    components = spec.get("components", {}).get("parameters", {})
    for param in components.values():
        if isinstance(param, dict) and should_join_query_param(param):
            name = param.get("name")
            if isinstance(name, str):
                comma_params.add(name)
    for item in spec.get("paths", {}).values():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            for param in operation.get("parameters", []):
                if not isinstance(param, dict) or "$ref" in param:
                    continue
                if should_join_query_param(param):
                    name = param.get("name")
                    if isinstance(name, str):
                        comma_params.add(name)
    return comma_params


def load_openapi_spec() -> dict:
    url = "https://api.x.com/2/openapi.json"
    LOGGER.info("Fetching OpenAPI spec from %s", url)
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    return response.json()


def should_exclude_operation(path: str, operation: dict) -> bool:
    if "/webhooks" in path or "/stream" in path:
        return True
    tags = [tag.lower() for tag in operation.get("tags", []) if isinstance(tag, str)]
    if "stream" in tags or "webhooks" in tags:
        return True
    if operation.get("x-twitter-streaming") is True:
        return True
    return False


def filter_openapi_spec(spec: dict) -> dict:
    filtered = copy.deepcopy(spec)
    paths = filtered.get("paths", {})
    new_paths = {}
    allow_tags = {tag.lower() for tag in parse_csv_env("X_API_TOOL_TAGS")}
    allow_ops = parse_csv_env("X_API_TOOL_ALLOWLIST")
    deny_ops = parse_csv_env("X_API_TOOL_DENYLIST")
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        new_item = {}
        for key, value in item.items():
            if key.lower() in HTTP_METHODS:
                if should_exclude_operation(path, value):
                    continue
                operation_id = value.get("operationId")
                operation_tags = [
                    tag.lower() for tag in value.get("tags", []) if isinstance(tag, str)
                ]
                if allow_tags and not (set(operation_tags) & allow_tags):
                    continue
                if allow_ops and operation_id not in allow_ops:
                    continue
                if deny_ops and operation_id in deny_ops:
                    continue
                new_item[key] = value
            else:
                new_item[key] = value
        if any(method.lower() in HTTP_METHODS for method in new_item.keys()):
            new_paths[path] = new_item
    filtered["paths"] = new_paths
    return filtered


def print_tool_list(spec: dict) -> None:
    tools: list[str] = []
    for path, item in spec.get("paths", {}).items():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            op_id = operation.get("operationId")
            tools.append(op_id or f"{method.upper()} {path}")
    tools.sort()
    print(f"Loaded {len(tools)} tools from OpenAPI:")
    for tool in tools:
        print(f"- {tool}")


# ---------------------------------------------------------------------------
# FastMCP server construction
# ---------------------------------------------------------------------------


def create_mcp() -> FastMCP:
    load_env()
    debug_enabled = setup_logging()

    client_id = os.getenv("X_OAUTH2_CLIENT_ID", "").strip()
    if not client_id:
        raise RuntimeError("X_OAUTH2_CLIENT_ID missing from .env")
    client_secret = os.getenv("X_OAUTH2_CLIENT_SECRET", "").strip() or None
    token_store = OAuth2TokenStore(client_id=client_id, client_secret=client_secret)

    base_url = os.getenv("X_API_BASE_URL", "https://api.x.com")
    timeout = float(os.getenv("X_API_TIMEOUT", "30"))

    spec = load_openapi_spec()
    filtered_spec = filter_openapi_spec(spec)
    comma_params = collect_comma_params(filtered_spec)
    if is_truthy(os.getenv("X_API_SLIM_SCHEMAS", "1")):
        slim_openapi_spec(filtered_spec, comma_params)
    print_tool_list(filtered_spec)

    async def normalize_query_params(request: httpx.Request) -> None:
        if not comma_params:
            return
        params = list(request.url.params.multi_items())
        grouped: dict[str, list[str]] = {}
        ordered: list[str] = []
        normalized: list[tuple[str, str]] = []
        for key, value in params:
            if key in comma_params:
                if key not in grouped:
                    ordered.append(key)
                grouped.setdefault(key, []).append(value)
            else:
                normalized.append((key, value))
        if not grouped:
            return
        for key in ordered:
            values: list[str] = []
            for raw in grouped[key]:
                for part in raw.split(","):
                    part = part.strip()
                    if part and part not in values:
                        values.append(part)
            if values:
                normalized.append((key, ",".join(values)))
        request.url = request.url.copy_with(params=normalized)

    async def attach_bearer(request: httpx.Request) -> None:
        token = await token_store.get_valid_bearer()
        request.headers["Authorization"] = f"Bearer {token}"

    async def log_request(request: httpx.Request) -> None:
        if debug_enabled:
            LOGGER.info("X API request %s %s", request.method, request.url)

    async def handle_response(response: httpx.Response) -> None:
        if response.status_code == 401:
            # Invalidate + refresh; the MCP caller will either retry via FastMCP
            # or the user will see a clean error and we'll pick up the new token
            # on the next request. Refreshing here keeps the store warm.
            LOGGER.warning("X API 401 — forcing token refresh")
            try:
                await token_store.invalidate_and_refresh()
            except Exception as exc:
                LOGGER.error("Refresh after 401 failed: %s", exc)
        if debug_enabled:
            LOGGER.info(
                "X API response %s %s -> %s",
                response.request.method, response.request.url, response.status_code,
            )
        if response.status_code >= 400:
            txid = response.headers.get("x-transaction-id")
            if txid:
                LOGGER.warning("X API x-transaction-id: %s", txid)
            body = await response.aread()
            text = body.decode("utf-8", errors="replace")
            if len(text) > 1000:
                text = text[:1000] + "...<truncated>"
            LOGGER.warning("X API error body: %s", text)

    client = httpx.AsyncClient(
        base_url=base_url,
        headers={},
        timeout=timeout,
        event_hooks={
            "request": [normalize_query_params, attach_bearer, log_request],
            "response": [handle_response],
        },
    )
    mcp = FastMCP.from_openapi(
        openapi_spec=filtered_spec,
        client=client,
        name="X API MCP",
    )
    if is_truthy(os.getenv("X_API_DROP_OUTPUT_SCHEMA", "1")):
        strip_output_schemas(mcp)
    return mcp


def strip_output_schemas(mcp: FastMCP) -> None:
    """Drop output_schema on each OpenAPI-derived tool. FastMCP derives it from
    X's response shape (~67 KB per tool), which pushes tools/list past Claude
    Desktop's payload cap. outputSchema is optional in MCP; invocation works
    the same without it."""
    count = 0
    for provider in getattr(mcp, "providers", []) or []:
        stored = getattr(provider, "_tools", None)
        if not isinstance(stored, dict):
            continue
        for tool in stored.values():
            try:
                tool.output_schema = None
                count += 1
            except Exception:
                pass
    LOGGER.info("Stripped output_schema on %d tools", count)


def main() -> None:
    host = os.getenv("MCP_HOST", "127.0.0.1")
    port = int(os.getenv("MCP_PORT", "8000"))
    mcp = create_mcp()
    mcp.run(transport="http", host=host, port=port)


if __name__ == "__main__":
    main()
