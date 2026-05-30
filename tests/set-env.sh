#!/bin/bash

if [[ -f .env ]]; then
  source .env
  export $(cat .env | sed 's/=.*//g'| xargs)
else
  source .env.example
  export $(cat .env.example | sed 's/=.*//g'| xargs)
fi

# Pin a unique Compose project name so this harness is isolated from sibling
# Jahia test stacks (which all otherwise default to project "tests"). Authoritative
# even on Compose versions that ignore the top-level `name:` in docker-compose.yml.
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-mfa-totp-factor-tests}"
