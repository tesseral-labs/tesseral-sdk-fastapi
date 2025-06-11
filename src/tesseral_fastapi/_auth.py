from typing import Optional

from tesseral import AccessTokenClaims, AuthenticateApiKeyResponse

from tesseral_fastapi._errors import NotAnAccessTokenError


class Auth:
    _access_token: Optional[str]
    _access_token_claims: Optional[AccessTokenClaims]
    _api_key_secret_token: Optional[str]
    _authenticate_api_key_response: Optional[AuthenticateApiKeyResponse]

    def credentials_type(self) -> str:
        if self._access_token:
            return "access_token"
        if self._api_key_secret_token:
            return "api_key"
        raise RuntimeError("Unreachable")

    def organization_id(self) -> str:
        if self._access_token_claims:
            return self._access_token_claims.organization.id
        if self._authenticate_api_key_response:
            return self._authenticate_api_key_response.organization_id
        raise RuntimeError("Unreachable")

    def access_token_claims(self) -> Optional[AccessTokenClaims]:
        if self._access_token_claims:
            return self._access_token_claims
        if self._authenticate_api_key_response:
            raise NotAnAccessTokenError()
        raise RuntimeError("Unreachable")

    def credentials(self) -> str:
        if self._access_token:
            return self._access_token
        if self._api_key_secret_token:
            return self._api_key_secret_token
        raise RuntimeError("Unreachable")

    def has_permission(self, action: str) -> bool:
        if self._access_token_claims:
            actions = self._access_token_claims.actions
            return bool(actions and action in actions)
        if self._authenticate_api_key_response:
            actions = self._authenticate_api_key_response.actions
            return bool(actions and action in actions)
        raise RuntimeError("Unreachable")
