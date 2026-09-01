from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI(title="Zero-Trust Agentic RAG/MCP Platform", docs_url=None, redoc_url=None)


@app.middleware("http")
async def headers(request, call_next):
    response = await call_next(request)
    response.headers.update(
        {
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        }
    )
    return response


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/.well-known/oauth-protected-resource")
def resource_metadata():
    return JSONResponse(
        {
            "resource": "http://127.0.0.1:8000/mcp",
            "authorization_servers": ["http://127.0.0.1:8080/realms/support"],
            "scopes_supported": [
                "kb:read",
                "tickets:read",
                "tickets:draft",
                "tickets:write",
                "messages:send",
                "cases:export",
            ],
        }
    )
