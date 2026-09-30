PG    := /opt/homebrew/opt/postgresql@18/bin
VENV  := .venv/bin
DB    ?= sentinel

.PHONY: setup migrate history reset qdrant scan enrich score triage \
        test lint fmt drift schema-dump prune stats ci clean

setup:                        ## create venv, install deps, fetch qdrant
	uv venv --python 3.12 .venv
	uv pip install -e ".[dev]"
	./scripts/fetch-qdrant.sh

migrate:                      ## apply migrations up to head
	$(VENV)/sentinel db migrate

history:                      ## show migration history
	$(VENV)/sentinel db history

reset:                        ## DESTRUCTIVE: drop everything, re-run migrations
	$(VENV)/sentinel db reset --yes

qdrant:                       ## run qdrant (native binary, no docker)
	./scripts/qdrant.sh

scan:                         ## generate fleet + trivy scan + load
	$(VENV)/sentinel fleet generate
	$(VENV)/sentinel scan

enrich:                       ## kev + epss (bulk) then nvd (rate limited)
	$(VENV)/sentinel enrich all

score:                        ## apply the deterministic risk policy
	$(VENV)/sentinel score

triage:                       ## show the prioritised queue
	$(VENV)/sentinel triage

stats:                        ## row counts
	$(VENV)/sentinel db stats

prune:                        ## drop factors from superseded assessments >90d
	$(VENV)/sentinel db prune

test:
	$(VENV)/pytest -q

lint:
	$(VENV)/ruff check src tests

fmt:
	$(VENV)/ruff format src tests

ci:                           ## run CI's checks locally (clean venv + clean db)
	./scripts/ci-local.sh

drift:                        ## verify migrations reproduce the live schema
	./scripts/check-schema-drift.sh

schema-dump:                  ## regenerate docs/schema.reference.sql
	./scripts/dump-schema.sh

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache
