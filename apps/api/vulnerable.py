"""Explicit synthetic vulnerable-lab HTTP entry point."""
from fastapi import FastAPI

app = FastAPI(title="INTENTIONALLY VULNERABLE SYNTHETIC LAB", docs_url=None, redoc_url=None)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "vulnerable-lab-only"}
