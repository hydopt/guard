SHELL := /bin/bash

SESSION_KEY ?= session-key.pem

.PHONY: gen-key

gen-key: ## Generate an ECDSA P-256 session signing key (sec1 PEM).
	@if [ -f "$(SESSION_KEY)" ]; then \
		echo "error: $(SESSION_KEY) already exists; delete it first to rotate" >&2; \
		exit 1; \
	fi; \
	openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null \
		| openssl ec 2>/dev/null > "$(SESSION_KEY)"; \
	chmod 600 "$(SESSION_KEY)"; \
	echo "wrote $(abspath $(SESSION_KEY)) (chmod 600)"
	@printf '\nNext steps:\n\n'
	@printf '1. Run the demo with a persistent session key (sessions survive restarts):\n'
	@printf '   GUARD_SESSION_KEY=%q make -C example/basic-auth run\n\n' "$${PWD}/$(SESSION_KEY)"
	@printf '2. In production, keep the key in a secret manager or mounted secret file and\n'
	@printf '   point GUARD_SESSION_KEY at the literal PEM or the file path:\n'
	@printf '   - GCP Secret Manager, AWS Secrets Manager, HashiCorp Vault, ...\n'
	@printf '   - docker-compose /run/secrets/... volumes (value-or-path reads the file)\n'
	@printf '3. Never commit the key to git.\n'
	@printf '4. Rotating or losing the key invalidates every outstanding session.\n'
	@printf '   To rotate: rm %s && make gen-key\n' "$(SESSION_KEY)"