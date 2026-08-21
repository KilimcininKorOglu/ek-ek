# Single command surface for development and CI.
#
# CI calls `make ci` and nothing else. A check therefore cannot exist in one
# place and be missing from the other, which is what produces "it worked on my
# machine".

SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

# Targets run in the order they are listed, never in parallel. `make ci` reports
# the first failing check, and a parallel run would interleave the output.
.NOTPARALLEL:

# Incremental compilation is off so that no check can pass on stale output.
export CARGO_INCREMENTAL := 0

CARGO ?= cargo
SCRIPTS := scripts

.PHONY: help
help: ## List every target
	@awk 'BEGIN { FS = ":.*##"; print "Usage: make <target>"; print "" } \
		/^[a-zA-Z0-9_-]+:.*##/ { printf "  %-16s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# --- Build and test ---------------------------------------------------------

.PHONY: build
build: ## Build the whole workspace
	$(CARGO) build --workspace

.PHONY: fmt
fmt: ## Format every source file
	$(CARGO) fmt --all

.PHONY: fmt-check
fmt-check: ## Fail if any source file is not formatted
	$(CARGO) fmt --all --check

.PHONY: lint
lint: ## Run clippy with warnings treated as errors
	$(CARGO) clippy --workspace --all-targets --all-features -- -D warnings

.PHONY: deny
deny: ## Check dependency licenses, advisories and sources
	$(CARGO) deny check

.PHONY: test
test: ## Run unit tests, never from cached results
	$(CARGO) test --workspace --all-features --no-fail-fast

# --- Repository checks ------------------------------------------------------

.PHONY: check-headers
check-headers: ## Verify the license header on every source file
	$(SCRIPTS)/check-license-headers.sh

.PHONY: check-apis
check-apis: ## Reject browser APIs the project has ruled out
	$(SCRIPTS)/check-forbidden-apis.sh

.PHONY: check-docs
check-docs: ## Warn when one half of a bilingual pair changed alone
	$(SCRIPTS)/check-bilingual-docs.sh

.PHONY: ci
ci: fmt-check lint deny check-headers check-apis check-docs test ## Run every check CI runs
	@echo "ci: all checks passed"

# --- Development environment (filled in by the docker environment task) ------

.PHONY: dev-up
dev-up: ## (pending) Start the three node development cluster
	@echo "dev-up is not implemented yet"
	@exit 1

.PHONY: dev-down
dev-down: ## (pending) Stop the cluster and remove its network
	@echo "dev-down is not implemented yet"
	@exit 1

.PHONY: dev-logs
dev-logs: ## (pending) Follow logs from the development cluster
	@echo "dev-logs is not implemented yet"
	@exit 1

.PHONY: dev-reset
dev-reset: ## (pending) Delete docker-data and rebuild the cluster from scratch
	@echo "dev-reset is not implemented yet"
	@exit 1

.PHONY: dev-test
dev-test: ## (pending) Run integration tests inside the docker environment
	@echo "dev-test is not implemented yet"
	@exit 1

# --- Reserved for later milestones ------------------------------------------

.PHONY: plan-index
plan-index: ## (pending) Regenerate the task index in plan/README.md
	@echo "plan-index is not implemented yet"
	@exit 1

.PHONY: plan-check
plan-check: ## (pending) Verify plan file consistency
	@echo "plan-check is not implemented yet"
	@exit 1

.PHONY: package
package: ## (pending) Build the deb and rpm packages
	@echo "package is not implemented yet"
	@exit 1

.PHONY: security-check
security-check: ## (pending) Run the security review checks
	@echo "security-check is not implemented yet"
	@exit 1
