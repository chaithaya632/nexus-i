.PHONY: install dev test lint clean format

install:
	pip install -e .

dev:
	pip install -e ".[dev,ai,dashboard,report,ml]"

test:
	pytest tests/ -v --tb=short

test-cov:
	pytest tests/ -v --cov=nexus --cov-report=term-missing

lint:
	ruff check nexus/ tests/
	ruff format --check nexus/ tests/

format:
	ruff format nexus/ tests/

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf build/ dist/ *.egg-info .pytest_cache .ruff_cache
