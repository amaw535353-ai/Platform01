PYTHONPATH := .
export PYTHONPATH
.PHONY: bootstrap up seed test security-test eval attack-report sbom scan down
bootstrap:
	uv sync --extra dev
up:
	docker compose -f deploy/compose/compose.yaml up -d --build
seed:
	@echo "Synthetic acme/globex fixtures are embedded deterministically; database migration: db/migrations/001_rls.sql"
test:
	uv run pytest
security-test:
	uv run pytest tests/security tests/unit/test_security_core.py
	uv run bandit -q -r packages apps services
eval:
	uv run pytest tests/security/test_attacks.py
attack-report:
	uv run python attack-lab/run.py
sbom:
	mkdir -p evidence && syft dir:. -o cyclonedx-json=evidence/sbom.cdx.json
scan:
	uv run ruff check .
	uv run mypy packages
	trivy fs --scanners vuln,secret,misconfig .
down:
	docker compose -f deploy/compose/compose.yaml --profile lab-vulnerable down -v

