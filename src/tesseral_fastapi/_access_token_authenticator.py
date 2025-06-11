import base64
import binascii
import json
import time
from typing import Optional, List, Dict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    EllipticCurvePublicNumbers,
    EllipticCurvePublicKey,
    ECDSA,
)
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256
from httpx import AsyncClient
from pydantic import BaseModel, ValidationError, Field
from tesseral.core import parse_obj_as
from tesseral.types.access_token_claims import AccessTokenClaims


class InvalidAccessTokenException(Exception):
    pass


class AsyncAccessTokenAuthenticator:
    _publishable_key: str
    _config_api_hostname: str
    _jwks_refresh_interval_seconds: int
    _http_client: AsyncClient
    _project_id: str
    _jwks: Dict[str, EllipticCurvePublicKey]
    _jwks_next_refresh_unix_seconds: float

    def __init__(
        self,
        *,
        publishable_key: str,
        config_api_hostname: str = "config.tesseral.com",
        jwks_refresh_interval_seconds: int = 3600,
        http_client: Optional[AsyncClient] = None,
    ):
        self._publishable_key = publishable_key
        self._config_api_hostname = config_api_hostname
        self._jwks_refresh_interval_seconds = jwks_refresh_interval_seconds
        self._http_client = http_client or AsyncClient()
        self._project_id = ""
        self._jwks = {}
        self._jwks_next_refresh_unix_seconds = 0

    async def project_id(self) -> str:
        await self._update_config()
        return self._project_id

    async def authenticate_access_token(
        self, *, access_token: str, now_unix_seconds: Optional[float] = None
    ) -> AccessTokenClaims:
        await self._update_config()
        return _authenticate_access_token(jwks=self._jwks, access_token=access_token, now_unix_seconds=now_unix_seconds)

    async def _update_config(self):
        if time.time() < self._jwks_next_refresh_unix_seconds:
            return

        response = await self._http_client.get(f"https://{self._config_api_hostname}/v1/config/{self._publishable_key}")
        response.raise_for_status()
        config = _parse_config(response.text)
        self._project_id = config.project_id
        self._jwks = config.jwks
        self._jwks_next_refresh_unix_seconds = time.time() + self._jwks_refresh_interval_seconds


def _authenticate_access_token(
    jwks: Dict[str, EllipticCurvePublicKey], access_token: str, now_unix_seconds: Optional[float] = None
) -> AccessTokenClaims:
    parts = access_token.split(".")
    if len(parts) != 3:
        raise _InvalidAccessTokenException()

    raw_header, raw_claims, raw_signature = parts
    try:
        parsed_header = _AccessTokenHeader.model_validate_json(_base64_url_decode(raw_header))
        parsed_signature = _base64_url_decode(raw_signature)
    except binascii.Error:
        raise _InvalidAccessTokenException()
    except ValidationError:
        raise _InvalidAccessTokenException()

    try:
        public_key = jwks[parsed_header.kid]
    except KeyError:
        raise _InvalidAccessTokenException()

    if len(parsed_signature) != 64:
        raise _InvalidAccessTokenException()

    r = int.from_bytes(parsed_signature[:32], byteorder="big")
    s = int.from_bytes(parsed_signature[32:], byteorder="big")
    signature = encode_dss_signature(r, s)
    try:
        public_key.verify(signature, (raw_header + "." + raw_claims).encode(), ECDSA(SHA256()))
    except InvalidSignature:
        raise _InvalidAccessTokenException()

    try:
        claims_json = json.loads(_base64_url_decode(raw_claims))
        parsed_claims = parse_obj_as(type_=AccessTokenClaims, object_=claims_json)
    except binascii.Error:
        raise _InvalidAccessTokenException()
    except ValidationError:
        raise _InvalidAccessTokenException()

    if now_unix_seconds is None:
        now_unix_seconds = time.time()

    # type assertions to appease mypy
    assert parsed_claims.nbf, _InvalidAccessTokenException()
    assert parsed_claims.exp, _InvalidAccessTokenException()
    if now_unix_seconds < parsed_claims.nbf or now_unix_seconds > parsed_claims.exp:
        raise _InvalidAccessTokenException()

    return parsed_claims


class _Config:
    project_id: str
    jwks: Dict[str, EllipticCurvePublicKey]


def _parse_config(config_json: str) -> _Config:
    config_parsed = _ConfigResponse.model_validate_json(config_json)
    jwks = {}
    for json_web_key in config_parsed.keys:
        assert json_web_key.kty == "EC"
        assert json_web_key.crv == "P-256"

        x = int.from_bytes(_base64_url_decode(json_web_key.x), byteorder="big")
        y = int.from_bytes(_base64_url_decode(json_web_key.y), byteorder="big")
        public_key = EllipticCurvePublicNumbers(curve=SECP256R1(), x=x, y=y).public_key()
        jwks[json_web_key.kid] = public_key

    config = _Config()
    config.project_id = config_parsed.project_id
    config.jwks = jwks
    return config


def _base64_url_decode(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


class _AccessTokenHeader(BaseModel):
    alg: str
    kid: str


class _JSONWebKey(BaseModel):
    kid: str
    kty: str
    crv: str
    x: str
    y: str


class _ConfigResponse(BaseModel):
    project_id: str = Field(alias="projectId")
    keys: List[_JSONWebKey]
