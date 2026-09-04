"""A minimal OAuth 2.1 authorization server, bolted onto the mock.

This exists because of a finding, not because it was planned. AWS documents a
"No authentication" option in three separate places on the MCP integration page
-- the Important callout, the authentication section, and step 6 of the setup
procedure -- and the Amazon Quick console offers only User and Service
authentication. An unauthenticated MCP server, which the protocol permits and
AWS says Quick supports, cannot be connected through that wizard.

The mock therefore has to present credentials in order to be connected at all.

Service authentication (client credentials) is chosen over user authentication
because it requires only a client identifier, a client secret and a token
endpoint, with no browser redirect, PKCE exchange, or callback URI
allow-listing.

This implementation provides no security and is not intended to. It issues a
token to any caller and the mock MCP server does not validate the token it
receives. These are not credentials; they satisfy a console requirement.
"""

from __future__ import annotations

import base64
import secrets
import time
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

# Fixed values, so that credentials entered into the Amazon Quick console remain
# valid across restarts of the mock server. They authorise nothing.
CLIENT_ID = "qs-preflight-mock-client"
CLIENT_SECRET = "mock-secret-not-a-real-credential"
SCOPES = ["mcp:tools"]

TOKEN_PATH = "/oauth/token"
PRM_PATH = "/.well-known/oauth-protected-resource"
ASM_PATH = "/.well-known/oauth-authorization-server"


def _issued_token() -> dict[str, Any]:
    return {
        "access_token": f"mock.{secrets.token_urlsafe(24)}",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": " ".join(SCOPES),
        "issued_at": int(time.time()),
    }


async def _token(request: Request) -> JSONResponse:
    """POST /oauth/token -- client_credentials grant.

    Deliberately permissive. Amazon Quick sends an RFC 8707 ``resource``
    parameter on token requests, and AWS documents Microsoft Entra ID rejecting
    requests carrying both ``resource`` and ``scope``. Any combination is
    accepted here, since refusing would produce a failure indistinguishable from
    the behaviour under measurement.
    """
    try:
        form = await request.form()
    except Exception:
        form = {}
    params = {k: v for k, v in form.items()}

    # Credentials may arrive in the body or as HTTP Basic, per OAuth 2.1.
    header = request.headers.get("authorization", "")
    if header.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(header[6:]).decode()
            cid, _, secret = decoded.partition(":")
            params.setdefault("client_id", cid)
            params.setdefault("client_secret", secret)
        except Exception:
            pass

    grant = params.get("grant_type", "")
    if grant and grant != "client_credentials":
        return JSONResponse(
            {"error": "unsupported_grant_type", "error_description": f"got {grant!r}"},
            status_code=400,
        )

    print(
        f"  [auth] token request  grant={grant or '(absent)'}  "
        f"client_id={params.get('client_id', '(absent)')}  "
        f"resource={params.get('resource', '(absent)')}  "
        f"scope={params.get('scope', '(absent)')}"
    )
    return JSONResponse(_issued_token())


def _prm(public_url: str):
    async def handler(request: Request) -> JSONResponse:
        print("  [auth] protected resource metadata fetched")
        return JSONResponse(
            {
                "resource": f"{public_url}/mcp",
                "authorization_servers": [public_url],
                "scopes_supported": SCOPES,
                "bearer_methods_supported": ["header"],
            }
        )

    return handler


def _asm(public_url: str):
    async def handler(request: Request) -> JSONResponse:
        print("  [auth] authorization server metadata fetched")
        return JSONResponse(
            {
                "issuer": public_url,
                "token_endpoint": f"{public_url}{TOKEN_PATH}",
                "authorization_endpoint": f"{public_url}/oauth/authorize",
                # Present so `dcr-available` would pass against this server.
                "registration_endpoint": f"{public_url}/oauth/register",
                "grant_types_supported": ["client_credentials", "authorization_code"],
                "response_types_supported": ["code"],
                "token_endpoint_auth_methods_supported": [
                    "client_secret_post",
                    "client_secret_basic",
                ],
                "code_challenge_methods_supported": ["S256"],
                "scopes_supported": SCOPES,
            }
        )

    return handler


async def _register(request: Request) -> JSONResponse:
    """Dynamic Client Registration, returning the single configured client."""
    print("  [auth] dynamic client registration attempted")
    return JSONResponse(
        {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "client_id_issued_at": int(time.time()),
            "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": "client_secret_post",
        },
        status_code=201,
    )


def routes(public_url: str) -> list[Route]:
    return [
        Route(TOKEN_PATH, _token, methods=["POST"]),
        Route(PRM_PATH, _prm(public_url), methods=["GET"]),
        Route(ASM_PATH, _asm(public_url), methods=["GET"]),
        Route("/oauth/register", _register, methods=["POST"]),
    ]


def console_values(public_url: str) -> list[tuple[str, str]]:
    """Exactly what to paste into the Quick console."""
    return [
        ("Client ID", CLIENT_ID),
        ("Client secret", CLIENT_SECRET),
        ("Token URL", f"{public_url}{TOKEN_PATH}"),
    ]
