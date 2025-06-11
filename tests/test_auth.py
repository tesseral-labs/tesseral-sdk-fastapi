import unittest

import pytest
from tesseral import AccessTokenClaims, AuthenticateApiKeyResponse
from tesseral.core import parse_obj_as

from tesseral_fastapi._auth import Auth
from tesseral_fastapi._errors import NotAnAccessTokenError


class TestAuth(unittest.TestCase):
    def test_credentials_type_with_access_token(self):
        auth = Auth()
        auth._access_token = "access_token_123"
        auth._api_key_secret_token = None
        auth._access_token_claims = None
        auth._authenticate_api_key_response = None
        self.assertEqual(auth.credentials_type(), "access_token")

    def test_credentials_type_with_api_key(self):
        auth = Auth()
        auth._access_token = None
        auth._api_key_secret_token = "api_key_456"
        auth._access_token_claims = None
        auth._authenticate_api_key_response = None
        self.assertEqual(auth.credentials_type(), "api_key")

    def test_organization_id_with_access_token(self):
        auth = Auth()
        auth._access_token = "access_token_123"
        auth._api_key_secret_token = None
        auth._access_token_claims = parse_obj_as(
            type_=AccessTokenClaims,
            object_={
                "organization": {"id": "org_123", "displayName": "Test Organization"},
                "user": {"id": "user_123", "email": "test@example.com"},
                "session": {"id": "session_123"},
                "iss": "https://example.com",
                "sub": "user_123",
                "aud": "https://example.com",
                "exp": 1741195468,
                "nbf": 1741195168,
                "iat": 1741195168,
            },
        )
        auth._authenticate_api_key_response = None
        self.assertEqual(auth.organization_id(), "org_123")

    def test_organization_id_with_api_key(self):
        auth = Auth()
        auth._access_token = None
        auth._api_key_secret_token = "api_key_456"
        auth._access_token_claims = None
        auth._authenticate_api_key_response = parse_obj_as(
            type_=AuthenticateApiKeyResponse, object_={"organization_id": "org_456"}
        )
        self.assertEqual(auth.organization_id(), "org_456")

    def test_access_token_claims_with_access_token(self):
        auth = Auth()
        auth._access_token = "access_token_123"
        auth._api_key_secret_token = None
        claims = parse_obj_as(
            type_=AccessTokenClaims,
            object_={
                "organization": {"id": "org_123", "displayName": "Test Organization"},
                "user": {"id": "user_123", "email": "test@example.com"},
                "session": {"id": "session_123"},
                "iss": "https://example.com",
                "sub": "user_123",
                "aud": "https://example.com",
                "exp": 1741195468,
                "nbf": 1741195168,
                "iat": 1741195168,
            },
        )
        auth._access_token_claims = claims
        auth._authenticate_api_key_response = None
        self.assertEqual(auth.access_token_claims(), claims)

    def test_access_token_claims_with_api_key(self):
        auth = Auth()
        auth._access_token = None
        auth._api_key_secret_token = "api_key_456"
        auth._access_token_claims = None
        auth._authenticate_api_key_response = parse_obj_as(
            type_=AuthenticateApiKeyResponse, object_={"organization_id": "org_456"}
        )
        with pytest.raises(NotAnAccessTokenError):
            auth.access_token_claims()

    def test_credentials_with_access_token(self):
        auth = Auth()
        auth._access_token = "access_token_123"
        auth._api_key_secret_token = None
        auth._access_token_claims = None
        auth._authenticate_api_key_response = None
        self.assertEqual(auth.credentials(), "access_token_123")

    def test_credentials_with_api_key(self):
        auth = Auth()
        auth._access_token = None
        auth._api_key_secret_token = "api_key_456"
        auth._access_token_claims = None
        auth._authenticate_api_key_response = None
        self.assertEqual(auth.credentials(), "api_key_456")

    def test_has_permission_with_access_token(self):
        auth = Auth()
        auth._access_token = "access_token_123"
        auth._api_key_secret_token = None
        auth._access_token_claims = parse_obj_as(
            type_=AccessTokenClaims,
            object_={
                "organization": {"id": "org_123", "displayName": "Test Organization"},
                "user": {"id": "user_123", "email": "test@example.com"},
                "session": {"id": "session_123"},
                "actions": ["a.b.c", "d.e.f"],
                "iss": "https://example.com",
                "sub": "user_123",
                "aud": "https://example.com",
                "exp": 1741195468,
                "nbf": 1741195168,
                "iat": 1741195168,
            },
        )
        auth._authenticate_api_key_response = None
        self.assertTrue(auth.has_permission("a.b.c"))
        self.assertTrue(auth.has_permission("d.e.f"))
        self.assertFalse(auth.has_permission("g.h.i"))

    def test_has_permission_with_api_key(self):
        auth = Auth()
        auth._access_token = None
        auth._api_key_secret_token = "api_key_456"
        auth._access_token_claims = None
        auth._authenticate_api_key_response = parse_obj_as(
            type_=AuthenticateApiKeyResponse,
            object_={
                "organization_id": "org_456",
                "actions": ["a.b.c", "d.e.f"],
            },
        )
        self.assertTrue(auth.has_permission("a.b.c"))
        self.assertTrue(auth.has_permission("d.e.f"))
        self.assertFalse(auth.has_permission("g.h.i"))

    def test_has_permission_with_empty_actions(self):
        auth = Auth()
        auth._access_token = "access_token_123"
        auth._api_key_secret_token = None
        auth._access_token_claims = parse_obj_as(
            type_=AccessTokenClaims,
            object_={
                "organization": {"id": "org_123", "displayName": "Test Organization"},
                "user": {"id": "user_123", "email": "test@example.com"},
                "session": {"id": "session_123"},
                "actions": None,
                "iss": "https://example.com",
                "sub": "user_123",
                "aud": "https://example.com",
                "exp": 1741195468,
                "nbf": 1741195168,
                "iat": 1741195168,
            },
        )
        auth._authenticate_api_key_response = None
        self.assertFalse(auth.has_permission("a.b.c"))

    def test_has_permission_with_empty_actions_api_key(self):
        auth = Auth()
        auth._access_token = None
        auth._api_key_secret_token = "api_key_456"
        auth._access_token_claims = None
        auth._authenticate_api_key_response = parse_obj_as(
            type_=AuthenticateApiKeyResponse,
            object_={
                "organization_id": "org_456",
                "actions": None,
            },
        )
        self.assertFalse(auth.has_permission("a.b.c"))


if __name__ == "__main__":
    unittest.main()
