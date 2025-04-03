from starlette.requests import Request
from tesseral import AccessTokenClaims


class _AuthContext:
    _access_token: str
    _access_token_claims: AccessTokenClaims


def extract_auth_context(name: str, request: Request) -> _AuthContext:
    assert "tesseral_auth" in request.scope, (
        f"Called {name}() on a request that does not carry auth data. Did you forget to use RequireAuthMiddleware?"
    )
    return request.scope["tesseral_auth"]


def organization_id(request: Request) -> str:
    return extract_auth_context(
        "organization_id", request
    )._access_token_claims.organization.id


def access_token_claims(request: Request) -> AccessTokenClaims:
    return extract_auth_context("access_token_claims", request)._access_token_claims


def credentials(request: Request) -> str:
    return extract_auth_context("credentials", request)._access_token
