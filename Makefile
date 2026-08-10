# Simple Makefile to help with things like formatting
# checks and installs

.PHONY: build
build: .installed

.PHONY: install
install: .installed
.installed:
	pip install ".[dev]"
	touch .installed

.PHONY: test
test: .installed
	pytest

lint: .installed
	isort --sp pyproject.toml -c pywebpush
	black --quiet --config pyproject.toml --check --target-version py314 pywebpush
	bandit --quiet -r -c pyproject.toml pywebpush

format: .installed
	isort --sp pyproject.toml pywebpush
	black --quiet --config pyproject.toml --target-version py314 pywebpush
	bandit --quiet -r -c pyproject.toml pywebpush


