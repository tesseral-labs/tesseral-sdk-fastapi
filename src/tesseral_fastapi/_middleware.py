from os import environ
from typing import Optional

from httpx import Client, AsyncClient
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from tesseral import AsyncTesseral, BadRequestError

from ._access_token_authenticator import AsyncAccessTokenAuthenticator, InvalidAccessTokenException
from ._auth import Auth
from ._credentials import is_jwt_format, is_api_key_format


class RequireAuthMiddleware(BaseHTTPMiddleware):
    """
    FastAPI/Starlette middleware that authenticates requests.

    Unauthenticated requests receive a 401 Unauthenticated error.

    Authenticated requests carry authentication data, which you can extract by
    having your handler take an argument annotated with Depends(get_auth).
    Requests will be required to be authenticated even if you do not extract an
    Auth instance in your handler.

    Args:
        app: The FastAPI/Starlette application to wrap with this middleware.
        publishable_key: The Tesseral publishable key for your project.
        config_api_hostname: The hostname of the Tesseral config API. Defaults to "config.tesseral.com".
        jwks_refresh_interval_seconds: How often to refresh the JWKS cache, in seconds. Defaults to 3600 (1 hour).
        http_client: Optional custom httpx.AsyncClient to use for requests. If not provided, a new client will be created.
        api_keys_enabled: Whether to enable API key authentication. Defaults to False.
        tesseral_client: Optional AsyncTesseral client to use for API key authentication. If not provided and
            api_keys_enabled is True, a new client will be created using the TESSERAL_BACKEND_API_KEY environment variable.

    Raises:
        RuntimeError: If api_keys_enabled is True but neither tesseral_client nor TESSERAL_BACKEND_API_KEY is provided.
    """

    def __init__(
            self,
            app,
            *,
            publishable_key,
            config_api_hostname="config.tesseral.com",
            jwks_refresh_interval_seconds: int = 3600,
            http_client: Optional[AsyncClient] = None,
            api_keys_enabled: bool = False,
            tesseral_client: Optional[AsyncTesseral] = None,
    ):
        if (
                api_keys_enabled
                and not tesseral_client
                and "TESSERAL_BACKEND_API_KEY" not in environ
        ):
            raise RuntimeError(
                "If you set api_keys_enabled to true, then you must either provide a tesseral_client or you must set a TESSERAL_BACKEND_API_KEY environment variable."
            )

        super().__init__(app)
        self.publishable_key = publishable_key
        self.config_api_hostname = config_api_hostname
        self.jwks_refresh_interval_seconds = jwks_refresh_interval_seconds
        self.http_client = http_client or AsyncClient()
        self.api_keys_enabled = api_keys_enabled
        self.tesseral_client = tesseral_client or AsyncTesseral()

        self.access_token_authenticator = AsyncAccessTokenAuthenticator(
            publishable_key=publishable_key,
            config_api_hostname=config_api_hostname,
            jwks_refresh_interval_seconds=jwks_refresh_interval_seconds,
            http_client=http_client,
        )

    async def dispatch(self, request: Request, call_next) -> Response:
        credential = _credential(request, await self.access_token_authenticator.project_id())
        if is_jwt_format(credential):
            try:
                access_token_claims = (
                    await self.access_token_authenticator.authenticate_access_token(
                        access_token=credential
                    )
                )
            except InvalidAccessTokenException:
                return JSONResponse({"error": "Unauthorized"}, status_code=401)
            except Exception as e:
                raise e

            auth = Auth()
            auth._access_token = credential
            auth._access_token_claims = access_token_claims
            request.state._tesseral_auth = auth
            return await call_next(request)
        elif self.api_keys_enabled and is_api_key_format(credential):
            try:
                authenticate_api_key_response = await self.tesseral_client.api_keys.authenticate_api_key(
                    secret_token=credential)
            except BadRequestError:
                return JSONResponse({"error": "Unauthorized"}, status_code=401)
            except Exception as e:
                raise e

            auth = Auth()
            auth._api_key_secret_token = credential
            auth._authenticate_api_key_response = authenticate_api_key_response
            request.state._tesseral_auth = auth
            return await call_next(request)

        return JSONResponse({"error": "Unauthorized"}, status_code=401)


def get_auth(request: Request) -> Auth:
    """
    Retrieves the Auth instance from the request.

    This function is intended to be used with FastAPI's Depends to inject
    an Auth instance into route handlers. The Auth instance is created by
    RequireAuthMiddleware.

    Args:
        request: The FastAPI/Starlette request object.

    Returns:
        Auth: The Auth instance containing authentication information.

    Raises:
        RuntimeError: If called outside RequireAuthMiddleware.
    """
    try:
        return request.state._tesseral_auth
    except KeyError:
        raise RuntimeError(
            "Called tesseral_fastapi.get_auth() outside of an authenticated request. Did you forget to use RequireAuthMiddleware?")


_PREFIX_BEARER = "Bearer "


def _credential(request: Request, project_id: str) -> str:
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.startswith(_PREFIX_BEARER):
        return auth_header[len(_PREFIX_BEARER):]

    cookie_name = f"tesseral_{project_id}_access_token"
    if cookie_name in request.cookies:
        return request.cookies[cookie_name]

    return ""
