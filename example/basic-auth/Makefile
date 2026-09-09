SHELL := /bin/bash

HURL ?= hurl
PORT ?= 8080

.PHONY: run test hurl

run: ## Launch the demo server (PORT env overrides).
	@test -n "$$GUARD_ORIGIN" || echo "hint: GUARD_ORIGIN defaults to http://localhost:$(PORT)"
	PORT="$(PORT)" go run .

test: ## Launch the demo server, wait for readiness, run the hurl suite.
	@set -euo pipefail; \
	go build -o .test-server .; \
	PORT="$(PORT)" ./.test-server & pid=$$!; \
	trap 'kill $$pid 2>/dev/null || true; rm -f .test-server' EXIT; \
	wait_ok=0; \
	for i in $$(seq 1 40); do \
		if curl -fsS -o /dev/null "http://localhost:$(PORT)/" 2>/dev/null; then wait_ok=1; break; fi; \
		sleep 0.25; \
	done; \
	[ $$wait_ok -eq 1 ] || { echo "server did not become ready on :$(PORT)" >&2; exit 1; }; \
	$(HURL) --test --variable base_url="http://localhost:$(PORT)" hurl/*.hurl

hurl: ## Run the hurl suite against an already-running server on $(PORT).
	$(HURL) --test --variable base_url="http://localhost:$(PORT)" hurl/*.hurl