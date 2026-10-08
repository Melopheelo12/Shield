SHIELD_STORAGE ?= postgres

.PHONY: help install dev lint format test test-integration test-cov types check run-api run-decoy fake load clean \
	qa qa-load qa-inputs qa-identity qa-egress

help:  ## Affiche cette aide
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	 awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install:  ## Installe le projet et ses dépendances de développement
	python -m venv .venv
	./.venv/bin/pip install -e ".[dev]"
	./.venv/bin/pre-commit install || true

lint:  ## ruff + black --check
	./.venv/bin/ruff check src tests
	./.venv/bin/black --check src tests

format:  ## Corrige automatiquement
	./.venv/bin/ruff check --fix src tests
	./.venv/bin/black src tests

test:  ## Tests unitaires
	./.venv/bin/pytest tests/unit

test-integration:  ## Tests d'intégration (PostgreSQL de DATABASE_URL, schéma jetable)
	./.venv/bin/pytest tests/integration

test-cov:  ## Tests + couverture sur les zones critiques
	./.venv/bin/pytest tests/unit \
	  --cov=shield.common.schema --cov=shield.collector.defender \
	  --cov=shield.collector.ingest --cov=shield.collector.enrichment \
	  --cov-report=term-missing --cov-fail-under=80

types:  ## Régénère les types TypeScript depuis les modèles Pydantic
	./.venv/bin/python -m shield.tools.gen_ts_types

check: lint test-cov  ## Tout ce que la CI vérifie, en local
	./.venv/bin/python -m shield.tools.gen_ts_types --check

run-api:  ## Lance le collecteur en local (port 8000) ; SHIELD_STORAGE=memory pour se passer de base
	INGEST_TOKEN=dev-token SHIELD_STORAGE=$(SHIELD_STORAGE) ./.venv/bin/uvicorn shield.collector.api.app:app --reload --port 8000

run-decoy:  ## Lance le leurre SSH en local (port 2222, sans privilège)
	INGEST_TOKEN=dev-token ./.venv/bin/python -m shield.decoys.runner ssh --port 2222

fake:  ## Flux d'événements factices vers le collecteur local
	./.venv/bin/python -m shield.tools.fake_events --token dev-token --rate 5

load:  ## Test de charge : 3 000 événements en 60 s (objectif F1)
	./.venv/bin/python -m shield.tools.fake_events --token dev-token --rate 50 --count 3000

qa-load:  ## Recette : 3 000 événements cadencés à 50/s (collecteur sur :8000)
	./.venv/bin/python scripts/qa/load_paced.py --count 3000 --rate 50

qa-inputs:  ## Recette : entrées malveillantes (leurres 2222/8080/2121 + collecteur)
	./.venv/bin/python scripts/qa/malicious_inputs.py

qa-identity:  ## Recette : aucune réponse des leurres ne trahit le honeypot
	./.venv/bin/python scripts/qa/identity_leaks.py

qa-egress:  ## Recette : aucune sortie possible depuis les conteneurs leurres
	./scripts/qa/decoy_egress.sh

qa: qa-load qa-inputs qa-identity  ## Recette locale complète (hors isolation Docker)

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage coverage.xml
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
