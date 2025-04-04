from typing import Optional

from httpx import AsyncClient
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Scope, Receive, Send
from tesseral.access_tokens import AsyncAccessTokenAuthenticator

from .context import _AuthContext, _auth_context_var

_PREFIX_BEARER = "Bearer "


class RequireAuthMiddleware:
    app: ASGIApp
    _access_token_authenticator: AsyncAccessTokenAuthenticator

    def __init__(
        self,
        app: ASGIApp,
        *,
        publishable_key: str,
        config_api_hostname: str = "config.tesseral.com",
        jwks_refresh_interval_seconds: int = 3600,
        http_client: Optional[AsyncClient] = None,
    ):
        self.app = app
        self._access_token_authenticator = AsyncAccessTokenAuthenticator(
            publishable_key=publishable_key,
            config_api_hostname=config_api_hostname,
            jwks_refresh_interval_seconds=jwks_refresh_interval_seconds,
            http_client=http_client,
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)
        project_id = await self._access_token_authenticator.project_id()
        access_token = self._access_token(request, project_id)

        try:
            access_token_claims = (
                await self._access_token_authenticator.authenticate_access_token(
                    access_token=access_token
                )
            )

            auth_context = _AuthContext()
            auth_context.access_token = access_token
            auth_context.access_token_claims = access_token_claims
        except:  # noqa: E722
            response = PlainTextResponse("Unauthorized\n", status_code=401)
            await response(scope, receive, send)
            return

        token = _auth_context_var.set(auth_context)
        await self.app(scope, receive, send)
        _auth_context_var.reset(token)

    def _access_token(self, request: Request, project_id: str) -> str:
        auth_header = request.headers.get("authorization")
        if auth_header and auth_header.startswith(_PREFIX_BEARER):
            return auth_header[len(_PREFIX_BEARER) :]

        cookie_name = f"tesseral_{project_id}_access_token"
        if cookie_name in request.cookies:
            return request.cookies[cookie_name]

        return ""
