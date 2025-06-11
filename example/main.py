from fastapi import FastAPI, Depends

from tesseral_fastapi import (
    RequireAuthMiddleware,
    Auth,
    get_auth,
)

app = FastAPI()

app.add_middleware(
    RequireAuthMiddleware,
    publishable_key="publishable_key_en43cawcravxk7t2murwiz192",
    config_api_hostname="config.tesseral.com",
)


@app.get("/")
async def read_root(auth: Auth = Depends(get_auth)):
    return {
        "credentials": auth.credentials(),
        "access_token_claims": auth.access_token_claims(),
        "organization_id": auth.organization_id(),
        "credentials_type": auth.credentials_type(),
        "has_permission": auth.has_permission("a.b.c"),
    }
