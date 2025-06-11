from typing import Optional

from tesseral import AccessTokenClaims, AuthenticateApiKeyResponse

from tesseral_fastapi._errors import NotAnAccessTokenError


class Auth:
    """
    Represents authentication information for a request.

    This class provides methods to access authentication details such as
    credentials type, organization ID, access token claims, and permissions.

    Auth instances require RequireAuthMiddleware to be added to the FastAPI app
    and should be acquired using Depends(get_auth) in FastAPI route handlers.
    """
    _access_token: Optional[str]
    _access_token_claims: Optional[AccessTokenClaims]
    _api_key_secret_token: Optional[str]
    _authenticate_api_key_response: Optional[AuthenticateApiKeyResponse]

    def credentials_type(self) -> str:
        """
        The type of authentication used in the request.

        Returns:
            str: Either "access_token" or "api_key".
        """
        if self._access_token:
            return "access_token"
        if self._api_key_secret_token:
            return "api_key"
        raise RuntimeError("Unreachable")

    def organization_id(self) -> str:
        """
        The ID of the organization the requester belongs to.

        Returns:
            str: The organization ID.
        """
        if self._access_token_claims:
            return self._access_token_claims.organization.id
        if self._authenticate_api_key_response:
            assert self._authenticate_api_key_response.organization_id  # appease mypy
            return self._authenticate_api_key_response.organization_id
        raise RuntimeError("Unreachable")

    def access_token_claims(self) -> AccessTokenClaims:
        """
        Returns the claims inside the request's access token.

        Returns:
            AccessTokenClaims: The claims from the access token.

        Raises:
            NotAnAccessTokenError: If the request was authenticated with an API key
                instead of an access token.
        """
        if self._access_token_claims:
            return self._access_token_claims
        if self._authenticate_api_key_response:
            raise NotAnAccessTokenError()
        raise RuntimeError("Unreachable")

    def credentials(self) -> str:
        """
        Returns the request's original credentials.

        Returns:
            str: The raw credential string (either access token or API key).
        """
        if self._access_token:
            return self._access_token
        if self._api_key_secret_token:
            return self._api_key_secret_token
        raise RuntimeError("Unreachable")

    def has_permission(self, action: str) -> bool:
        """
        Returns true if the requester has permission to carry out the given action.
        Returns false otherwise.

        Args:
            action: An action name, such as "acme.widgets.edit".

        Returns:
            bool: True if the requester has the specified permission, False otherwise.
        """
        if self._access_token_claims:
            actions = self._access_token_claims.actions
            return bool(actions and action in actions)
        if self._authenticate_api_key_response:
            actions = self._authenticate_api_key_response.actions
            return bool(actions and action in actions)
        raise RuntimeError("Unreachable")
