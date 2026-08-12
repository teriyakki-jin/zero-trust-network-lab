import json
import logging
import os
from typing import Any
from uuid import uuid4

import httpx
import jwt
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError


OIDC_ISSUER = os.environ["OIDC_ISSUER"].rstrip("/")
OIDC_AUDIENCE = os.environ["OIDC_AUDIENCE"]
OIDC_JWKS_URL = os.environ["OIDC_JWKS_URL"]
OPA_DECISION_URL = os.environ["OPA_DECISION_URL"]
UPSTREAM_URL = os.environ["UPSTREAM_URL"].rstrip("/")
POSTURE_MODE = os.getenv("POSTURE_MODE", "disabled")
MAX_BODY_BYTES = int(os.getenv("MAX_BODY_BYTES", "1048576"))

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("zero-trust-pep")
jwks_client = PyJWKClient(OIDC_JWKS_URL, cache_jwk_set=True, lifespan=300)

app = FastAPI(title="Zero Trust Lab PEP", docs_url=None, redoc_url=None)


def log_event(**fields: Any) -> None:
    logger.info(json.dumps(fields, ensure_ascii=False, separators=(",", ":")))


def clean_header_value(value: str) -> str:
    return value.replace("\r", "").replace("\n", "")[:256]


def parse_bool(value: str | None) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes"}


def parse_bounded_int(value: str | None, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value) if value is not None else default
    except ValueError:
        return default
    return max(minimum, min(parsed, maximum))


def bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token.strip()


def verify_token(token: str) -> dict[str, Any]:
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    return jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=OIDC_AUDIENCE,
        issuer=OIDC_ISSUER,
        options={"require": ["exp", "iat", "sub"]},
        leeway=5,
    )


def simulated_posture(request: Request) -> dict[str, Any]:
    if POSTURE_MODE != "simulation":
        return {"managed": False, "edr": "unknown", "patch_age_days": 999}
    return {
        "managed": parse_bool(request.headers.get("x-device-managed")),
        "edr": clean_header_value(request.headers.get("x-edr-status", "unknown")).lower(),
        "patch_age_days": parse_bounded_int(
            request.headers.get("x-patch-age-days"), default=999, minimum=0, maximum=999
        ),
    }


async def policy_decision(policy_input: dict[str, Any]) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=2.5) as client:
        response = await client.post(OPA_DECISION_URL, json={"input": policy_input})
        response.raise_for_status()
        payload = response.json()
    decision = payload.get("result")
    if not isinstance(decision, dict) or not isinstance(decision.get("allow"), bool):
        raise ValueError("OPA returned an invalid decision")
    return decision


async def bounded_request_body(request: Request) -> bytes:
    content_length = request.headers.get("content-length")
    if content_length is not None and parse_bounded_int(content_length, 0, 0, MAX_BODY_BYTES + 1) > MAX_BODY_BYTES:
        raise ValueError("request_too_large")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_BODY_BYTES:
            raise ValueError("request_too_large")
    return bytes(body)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def enforce(request: Request, path: str) -> Response:
    request_id = str(uuid4())
    token = bearer_token(request)
    if token is None:
        log_event(event="access_denied", request_id=request_id, reason="missing_token")
        return JSONResponse({"error": "missing_token", "request_id": request_id}, status_code=401)

    try:
        claims = verify_token(token)
    except PyJWKClientConnectionError as exc:
        log_event(event="access_denied", request_id=request_id, reason="identity_provider_unavailable", detail=type(exc).__name__)
        return JSONResponse({"error": "identity_provider_unavailable", "request_id": request_id}, status_code=503)
    except (jwt.PyJWTError, PyJWKClientError) as exc:
        log_event(event="access_denied", request_id=request_id, reason="invalid_token", detail=type(exc).__name__)
        return JSONResponse({"error": "invalid_token", "request_id": request_id}, status_code=401)
    except Exception as exc:
        log_event(event="access_denied", request_id=request_id, reason="identity_provider_unavailable", detail=type(exc).__name__)
        return JSONResponse({"error": "identity_provider_unavailable", "request_id": request_id}, status_code=503)

    username = clean_header_value(str(claims.get("preferred_username", "")))
    roles = claims.get("realm_access", {}).get("roles", [])
    if not isinstance(roles, list):
        roles = []

    policy_input = {
        "user": {
            "sub": str(claims.get("sub", "")),
            "username": username,
            "roles": [str(role) for role in roles],
        },
        "device": simulated_posture(request),
        "risk_score": parse_bounded_int(
            request.headers.get("x-risk-score"), default=100, minimum=0, maximum=100
        ),
        "request": {"method": request.method, "path": f"/{path}"},
    }

    try:
        decision = await policy_decision(policy_input)
    except Exception as exc:
        log_event(event="access_denied", request_id=request_id, username=username, reason="policy_engine_unavailable", detail=type(exc).__name__)
        return JSONResponse({"error": "policy_engine_unavailable", "request_id": request_id}, status_code=503)

    if not decision["allow"]:
        reason = str(decision.get("reason", "policy_denied"))
        log_event(event="access_denied", request_id=request_id, username=username, reason=reason)
        return JSONResponse({"error": reason, "request_id": request_id}, status_code=403)

    try:
        body = await bounded_request_body(request)
    except ValueError:
        return JSONResponse({"error": "request_too_large", "request_id": request_id}, status_code=413)

    upstream = f"{UPSTREAM_URL}/{path.lstrip('/')}"
    forwarded_headers = {
        "x-zt-sub": clean_header_value(str(claims.get("sub", ""))),
        "x-zt-user": username,
        "x-zt-request-id": request_id,
        "accept": request.headers.get("accept", "application/json"),
    }
    if content_type := request.headers.get("content-type"):
        forwarded_headers["content-type"] = content_type

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            upstream_response = await client.request(
                request.method,
                upstream,
                params=request.query_params,
                content=body,
                headers=forwarded_headers,
            )
    except httpx.HTTPError as exc:
        log_event(event="upstream_error", request_id=request_id, username=username, detail=type(exc).__name__)
        return JSONResponse({"error": "upstream_unavailable", "request_id": request_id}, status_code=502)

    log_event(
        event="access_allowed",
        request_id=request_id,
        username=username,
        method=request.method,
        path=f"/{path}",
        status=upstream_response.status_code,
        session_ttl_seconds=decision.get("session_ttl_seconds", 0),
    )
    response_headers = {"x-zt-request-id": request_id, "cache-control": "no-store"}
    if upstream_response.headers.get("content-type"):
        response_headers["content-type"] = upstream_response.headers["content-type"]
    return Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers=response_headers,
    )
