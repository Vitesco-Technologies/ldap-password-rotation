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
setup: clean ## Set up dependencies
	echo python version: $$(which python3.9) 
	@(PIPENV_VERBOSITY=-1 pipenv --venv && PIPENV_VERBOSITY=-1 PIPENV_VENV_IN_PROJECT=1 pipenv --rm) || true >/dev/null
	CFLAGS=$(CFLAGS) LC_ALL=$(LC_ALL) LANG=$(LANG) PIPENV_VENV_IN_PROJECT=1 pipenv sync --dev --python=$$(which python3.9)
	npm install
	# make setenv

.PHONY: setenv
setenv: ## Set up dependencies
	touch .env
	rm .env
	npx sls export-env
	sed -i.tmp "s|https://api.datalake-dev.aws1581.vitesco.io|http://localhost:5006|g" .env
	rm .env.tmp

.PHONY: clean
clean:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '.cache' -exec rm -rf {} +
	find . -name '__pycache__' -exec rm -rf {} +
	find . -name '.pytest*' -exec rm -rf {} +
	find . -name '.tox' -exec rm -rf {} +
	find . -name '*.egg-info' -exec rm -rf {} +
	find . -name '.eggs' -exec rm -rf {} +
	find . -name '.requirements' -exec rm -rf {} +
	find . -name '.serverless' -exec rm -rf {} +
	find . -name '.coverage' -exec rm -rf {} +
	find . -name '.pytest_cache' -exec rm -rf {} +
	rm -rf build +
	rm -rf dist +


.PHONY: update-file-ref
update-file-ref: ## Update file references
	pipenv uninstall datalakeservices
	pipenv install -e ./../datalake-services 

.PHONY: start
start: ## Start development env with sls wsgi plugin
	cd src && pipenv run uvicorn main:app --port 5008 --host 0.0.0.0 --reload

.PHONY: deploy
deploy: ## Deploy with serverless framework
	@[ "${stage}" ] || ( echo ">> stage is not set call with make deploy stage=<app stage>"; exit 1 )
	rm -rf layer/python/
	pipenv run pip install -r <(pipenv requirements) --target layer/python
	pipenv run npx sls deploy --stage=${stage}

.PHONY: undeploy
undeploy: ## undeploy with serverless framework
	@[ "${stage}" ] || ( echo ">> stage is not set call with make deploy stage=<app stage>"; exit 1 )
	pipenv run sls remove --stage=${stage}

.PHONY: format
format: ## Format code
	pipenv run isort bucket tests testsuite
	pipenv run yapf -i -r bucket tests testsuite

.PHONY: tests
tests: ## Run tests
	pipenv run tests

.PHONY: healthcheck
healthcheck: ## Run tests
	sls invoke -f app --data '{"resource": "/",  "path": "/api",  "httpMethod": "GET",  "requestContext": {  },  "multiValueQueryStringParameters": null}' 
