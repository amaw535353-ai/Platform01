FROM python:3.12.11-slim@sha256:47ae396f09c1303b8653019811a8498470603d7ffefc29cb07c88f1f8cb3d19f
RUN useradd --create-home --uid 10001 app
WORKDIR /app
COPY pyproject.toml README.md ./
COPY packages ./packages
COPY apps ./apps
RUN pip install --no-cache-dir uv==0.12.8 && uv sync --no-dev && rm -rf /root/.cache
USER 10001
ENV PATH="/app/.venv/bin:$PATH"
HEALTHCHECK --interval=5s --timeout=2s --retries=10 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=1)"
CMD ["uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
