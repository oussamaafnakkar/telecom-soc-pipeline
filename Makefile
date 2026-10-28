COMPOSE ?= docker compose

.DEFAULT_GOAL := help
.PHONY: help build test up verify e2e logs ps down reset

help: ## Show this help
	@grep -E '^[a-z0-9_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  %-8s %s\n", $$1, $$2}'

build: ## Build the tools image
	$(COMPOSE) build

test: ## Run the detection tests in Docker (fast, no Elasticsearch needed)
	$(COMPOSE) run --rm tests

up: ## Start Elasticsearch, Logstash and Kibana with fresh fixtures
	$(COMPOSE) up -d --build

verify: ## Check the running stack indexed and tagged the data correctly
	$(COMPOSE) run --rm verify

e2e: reset up verify ## Clean slate, start the stack, verify it (leaves the stack running)

logs: ## Show the last 100 log lines of every service
	$(COMPOSE) logs --tail=100

ps: ## Show service status
	$(COMPOSE) ps -a

down: ## Stop the stack, keep the data
	$(COMPOSE) down

reset: ## Stop the stack and delete all data (Elasticsearch index, fixtures)
	$(COMPOSE) down -v
