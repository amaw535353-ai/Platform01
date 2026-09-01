FROM python:3.12.11-slim@sha256:6d4b7f0e2f6f8f7d55b530fda0c995ad83f9483e6d7f90f4f20492798ef39b1c
RUN useradd --create-home --uid 10001 app
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY packages ./packages
COPY apps ./apps
RUN pip install --no-cache-dir uv==0.7.22 && uv sync --frozen --no-dev && rm -rf /root/.cache
USER 10001
ENV PATH="/app/.venv/bin:$PATH"
HEALTHCHECK --interval=5s --timeout=2s --retries=10 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=1)"
CMD ["uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
