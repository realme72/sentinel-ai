PG := /opt/homebrew/opt/postgresql@16/bin
VENV := .venv/bin

.PHONY: setup db qdrant test lint fmt clean

setup:
	uv venv --python 3.12 .venv
	uv pip install -e ".[dev]"
	./scripts/fetch-qdrant.sh

db:
	$(PG)/createdb sentinel 2>/dev/null || true
	$(PG)/psql -d sentinel -v ON_ERROR_STOP=1 -f src/sentinel/db/schema.sql

qdrant:
	./scripts/qdrant.sh

test:
	$(VENV)/pytest -q

lint:
	$(VENV)/ruff check src tests evals

fmt:
	$(VENV)/ruff format src tests evals

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache
