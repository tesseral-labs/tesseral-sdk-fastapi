from fastapi import FastAPI, Depends

from tesseral_fastapi import (
    RequireAuthMiddleware,
    Auth,
    get_auth,
    NotAnAccessTokenError,
)

app = FastAPI()

app.add_middleware(
    RequireAuthMiddleware,
    publishable_key="publishable_key_en43cawcravxk7t2murwiz192",
    api_keys_enabled=True,
)


@app.get("/")
async def read_root(auth: Auth = Depends(get_auth)):
    try:
        access_token_claims = auth.access_token_claims()
    except NotAnAccessTokenError:
        access_token_claims = None

    return {
        "credentials": auth.credentials(),
        "access_token_claims": access_token_claims,
        "organization_id": auth.organization_id(),
        "credentials_type": auth.credentials_type(),
        "has_permission": auth.has_permission("a.b.c"),
    }
