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
	python -c "import pathlib, shutil; [shutil.rmtree(p, ignore_errors=True) for p in list(pathlib.Path('.').rglob('__pycache__')) + list(pathlib.Path('.').glob('*.egg-info')) + [pathlib.Path(d) for d in ('build', 'dist', '.pytest_cache', '.ruff_cache')] if p.exists()]; [p.unlink(missing_ok=True) for p in pathlib.Path('.').rglob('*.pyc')]"
