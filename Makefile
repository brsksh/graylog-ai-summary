# Graylog AI Summary – local development & test
# Prefer Python 3.12, then 3.11, then python3
PYTHON := $(shell command -v python3.12 2>/dev/null || command -v python3.11 2>/dev/null || command -v python3)
VENV   := .venv
PY     := $(VENV)/bin/python
PIP    := $(VENV)/bin/pip

.PHONY: venv install test run help

help:
	@echo "Graylog AI Summary (Python: $(PYTHON))"
	@echo ""
	@echo "  make venv     – create .venv"
	@echo "  make install  – venv + install requirements"
	@echo "  make test     – dry run (Graylog + Ollama, no delivery)"
	@echo "  make run      – full run (Telegram/Slack as configured)"
	@echo ""

venv:
	@$(PYTHON) -m venv $(VENV)
	@echo "✓ $(VENV) created with $(PYTHON). Run: make install"

install: venv
	$(PIP) install -r requirements.txt
	@echo "✓ Dependencies installed. Run: make test"

test: install
	$(PY) log_summary.py --config config.yaml --dry-run

run: install
	$(PY) log_summary.py --config config.yaml
