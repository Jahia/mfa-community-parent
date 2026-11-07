#!/bin/bash

# The cypress service runs in cypress/included:<v>, which only ships the Cypress <v> binary: the
# image must follow the "cypress" version pinned in package.json, or `yarn cypress run` finds no
# binary (and a too-old image also has a Node that newer devDependencies refuse). Derive it here,
# BEFORE .env/.env.example are sourced, so a Dependabot bump of cypress moves the image in the
# same PR. An explicit TESTS_IMAGE (shell or .env) still wins.
_cypress_version="$(sed -n 's/^ *"cypress": *"\([0-9][0-9.]*\)".*/\1/p' "$(dirname "${BASH_SOURCE[0]}")/package.json")"
if [[ -z "${TESTS_IMAGE:-}" && -n "${_cypress_version}" ]]; then
  export TESTS_IMAGE="cypress/included:${_cypress_version}"
fi
unset _cypress_version

if [[ -f .env ]]; then
  source .env
  export $(grep -v '^\s*#' .env | grep -v '^\s*$' | sed 's/=.*//g'| xargs)
else
  source .env.example
  export $(grep -v '^\s*#' .env.example | grep -v '^\s*$' | sed 's/=.*//g'| xargs)
fi

# Pin a unique Compose project name so this harness is isolated from sibling
# Jahia test stacks (which all otherwise default to project "tests"). Authoritative
# even on Compose versions that ignore the top-level `name:` in docker-compose.yml.
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-mfa-totp-factor-tests}"
