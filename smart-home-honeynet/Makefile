.PHONY: help install test demo serve analyze lint clean compose-up compose-down

PYTHON ?= python3
export PYTHONPATH := src

help:
	@echo "SmartHoneyNet — make targets"
	@echo "  make install       Install runtime + dev dependencies"
	@echo "  make test          Run the pytest suite"
	@echo "  make demo          Run the self-contained end-to-end demo"
	@echo "  make serve         Start the honeypots + detection pipeline"
	@echo "  make analyze       Generate a Markdown report from honeynet.db"
	@echo "  make compose-up    Launch the full honeypot + ELK stack (Docker)"
	@echo "  make compose-down  Tear down the Docker stack"
	@echo "  make clean         Remove generated databases, logs and reports"

install:
	$(PYTHON) -m pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest -q

demo:
	$(PYTHON) -m honeynet demo

serve:
	$(PYTHON) -m honeynet serve

analyze:
	$(PYTHON) -m honeynet analyze --db honeynet.db --out reports/analysis.md

compose-up:
	docker compose up -d --build

compose-down:
	docker compose down

clean:
	rm -f *.db demo.db honeynet.db
	rm -rf logs reports __pycache__ .pytest_cache
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
