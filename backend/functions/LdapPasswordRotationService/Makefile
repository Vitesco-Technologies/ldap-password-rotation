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
	echo python version: $$(which python3.9) 
	@(PIPENV_VERBOSITY=-1 pipenv --venv && PIPENV_VERBOSITY=-1 PIPENV_VENV_IN_PROJECT=1 pipenv --rm) || true >/dev/null
	CFLAGS=$(CFLAGS) LC_ALL=$(LC_ALL) LANG=$(LANG) PIPENV_VENV_IN_PROJECT=1 pipenv sync --dev --python=$$(which python3.9)
	npm install

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

.PHONY: tests
tests: ## Run tests
	pipenv run tests

.PHONY: healthcheck
healthcheck: ## Run tests
	sls invoke -f app --data '{"resource": "/",  "path": "/api",  "httpMethod": "GET",  "requestContext": {  },  "multiValueQueryStringParameters": null}' 
