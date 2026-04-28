# Copyright 2024 Daniel Dias, Vitesco Technologies
#
# SPDX-License-Identifier: Apache-2.0
SHELL := /bin/bash
.DEFAULT_GOAL := help

#######################
# HELPER TARGETS
#######################

.PHONY: help
help:  ## Show available commands
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) |  awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

#######################
# DEVELOPMENT TARGETS
#######################

.PHONY: setup
setup: ## Set up dependencies
	echo python version: $$(which python3.13) 
	uv sync --python=$$(which python3.13)
	bun install --frozen-lockfile

.PHONY: update
update: ## Update dependencies
	echo python version: $$(which python3.13) 
	uv lock --upgrade
	uv sync --python=$$(which python3.13)
	bun update
	uv export --format requirements.txt --no-hashes --no-dev --output-file requirements.txt
	uv export --format requirements.txt --no-hashes --all-groups --output-file requirements-dev.txt

.PHONY: deploy
deploy: ## Deploy with serverless framework
	@[ "${stage}" ] || ( echo ">> stage is not set call with make deploy stage=<app stage>"; exit 1 )
	rm -rf layer/python/
	uv pip install --python=$$(which python3.13) -r requirements.txt --target layer/python
	bunx sls deploy --stage=${stage} --verbose

.PHONY: undeploy
undeploy: ## undeploy with serverless framework
	@[ "${stage}" ] || ( echo ">> stage is not set call with make deploy stage=<app stage>"; exit 1 )
	bunx sls remove --stage=${stage}

.PHONY: test
test:
	uv run pytest --cov-report term-missing --cov

.PHONY: test-log
test-log:
	uv run pytest --cov-report term-missing --cov -vs --log-cli-level info

.PHONY: requirements
requirements: ## Create requirements.txt
	uv export --format requirements.txt --no-hashes --no-dev --output-file requirements.txt
	uv export --format requirements.txt --no-hashes --all-groups --output-file requirements-dev.txt