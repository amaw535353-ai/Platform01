FROM python:3.12.11-slim@sha256:6d4b7f0e2f6f8f7d55b530fda0c995ad83f9483e6d7f90f4f20492798ef39b1c
RUN useradd --create-home --uid 10001 app
WORKDIR /app
COPY . .
USER 10001
CMD ["python", "-m", "uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

