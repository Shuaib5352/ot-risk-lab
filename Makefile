.PHONY: install-dev check test coverage benchmark build release-check docker-build

install-dev:
	python -m pip install -e ".[dev]"

check:
	ruff check src tests scripts
	python -m compileall -q src tests scripts
	python scripts/release_check.py

test:
	python -m unittest discover -s tests -v

coverage:
	coverage run -m unittest discover -s tests -v
	coverage report --fail-under=80

benchmark:
	PYTHONPATH=src python -m ot_risk_lab benchmark examples/benchmark_suite.json

build:
	python -m build

release-check: check coverage benchmark
	docker build -t ot-risk-lab:local .

docker-build:
	docker build -t ot-risk-lab:local .
