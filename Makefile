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
# ek-ek-itest is excluded because it drives docker and needs a running
# cluster. `make lint` still compiles it, so a broken harness fails here.
	$(CARGO) test --workspace --exclude ek-ek-itest --all-features --no-fail-fast

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

.PHONY: check-secrets
check-secrets: ## Refuse credentials in tracked files
	$(SCRIPTS)/check-secrets.sh

.PHONY: check-layering
check-layering: ## Enforce the crate dependency direction
	$(SCRIPTS)/check-layering.sh

.PHONY: ci
ci: fmt-check lint deny check-headers check-apis check-docs check-secrets check-layering test ## Run every check CI runs
	@echo "ci: all checks passed"

# --- Development environment ------------------------------------------------

# --env-file is explicit on purpose. Compose looks for .env next to the compose
# file, not in the project root, so without this HOST_UID silently falls back to
# its default and the bind mount fills with files owned by the wrong user.
COMPOSE := docker compose --env-file .env -f docker/compose.yml
DATA := docker-data
NODES := node1 node2 node3
BACKENDS := backend1 backend2
# The builder writes here as the host user, so the directories must exist
# and be owned by that user before the container mounts them.
BUILDER_DIRS := builder-cargo builder-target

.PHONY: dev-env
dev-env: ## Create .env and the docker-data directories if they are missing
	@if [ ! -f .env ]; then \
		sed -e "s/^HOST_UID=$$/HOST_UID=$$(id -u)/" \
		    -e "s/^HOST_GID=$$/HOST_GID=$$(id -g)/" \
		    .env.example > .env; \
		echo "created .env from .env.example"; \
		echo "set EK_EK_ADMIN_PASSWORD in .env before bootstrapping a cluster"; \
	fi
	@mkdir -p $(addprefix $(DATA)/,$(NODES) $(BACKENDS) $(BUILDER_DIRS))
	@for b in $(BACKENDS); do \
		if [ ! -f $(DATA)/$$b/index.html ]; then \
			echo "$$b" > $(DATA)/$$b/index.html; \
		fi; \
	done

.PHONY: dev-up
dev-up: dev-env ## Start the three node development cluster
	$(COMPOSE) up -d --build
	@echo "cluster is up; run 'make dev-verify' to check its preconditions"

.PHONY: dev-down
dev-down: dev-env ## Stop the cluster and remove its network, keeping docker-data
	$(COMPOSE) down --remove-orphans

.PHONY: dev-logs
dev-logs: dev-env ## Follow logs from the development cluster
	$(COMPOSE) logs -f

.PHONY: dev-verify
dev-verify: dev-env ## Prove the preconditions the product depends on
	$(SCRIPTS)/verify-dev-env.sh

# Destructive: it deletes the persistent development data. It says what it will
# remove and waits for confirmation, because a wrong keystroke here costs a
# cluster that took several manual steps to build.
.PHONY: dev-reset
dev-reset: ## Delete docker-data and rebuild the cluster from scratch
	@echo "This deletes the development cluster and everything under $(DATA)/:"
	@for d in $(NODES) $(BACKENDS) $(BUILDER_DIRS); do \
		printf '  %s (%s)\n' "$(DATA)/$$d" "$$(du -sh $(DATA)/$$d 2>/dev/null | cut -f1 || echo missing)"; \
	done
	@read -r -p "Type 'sil' to confirm: " answer; \
	if [ "$$answer" != "sil" ]; then echo "cancelled"; exit 1; fi; \
	$(COMPOSE) down -v --remove-orphans; \
	rm -rf $(DATA)
	@$(MAKE) --no-print-directory dev-up
	@echo "cluster rebuilt from scratch"

# Serial on purpose: the tests share one bridge network, one VIP range and
# one set of node containers, so running them in parallel would have them
# tear down each other's state.
.PHONY: dev-test
dev-test: dev-env ## Run integration tests against the docker environment
	$(CARGO) test -p ek-ek-itest --all-features --no-fail-fast -- --test-threads=1

# --- Reserved for later milestones ------------------------------------------

# plan/ is not tracked by git (ADR-0047), so these run locally only and are
# deliberately absent from `make ci`: a CI checkout has no plan files.
.PHONY: plan-index
plan-index: ## Regenerate the task index in plan/README.md
	python3 $(SCRIPTS)/plan_index.py

.PHONY: plan-check
plan-check: ## Verify plan file consistency
	python3 $(SCRIPTS)/plan_index.py --check

.PHONY: package
package: ## (pending) Build the deb and rpm packages
	@echo "package is not implemented yet"
	@exit 1

.PHONY: security-check
security-check: ## (pending) Run the security review checks
	@echo "security-check is not implemented yet"
	@exit 1
