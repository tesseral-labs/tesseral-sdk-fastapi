from fastapi import FastAPI, Request

from tesseral_fastapi import RequireAuthMiddleware, credentials, access_token_claims, organization_id

app = FastAPI()

app.add_middleware(RequireAuthMiddleware, publishable_key="publishable_key_7nvw48k6r4wazcpna9stb8tid", config_api_hostname="config.tesseral.com")


@app.get("/")
async def read_root(request: Request):
    return {"credentials": credentials(request), "access_token_claims": access_token_claims(request).organization.display_name, "organization_id": organization_id(request)}

