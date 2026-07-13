#!/bin/bash
#
# Bring up Jahia + Cypress + smtp-server, wait for Jahia, provision, and run the Cypress suite
# in TWO phases, then tear down.
#
#   Phase 1 (all-factors stack)  — the whole suite EXCEPT ui.webauthn.softWire.cy.ts.
#   Phase 2 (TOTP-only stack)    — ONLY ui.webauthn.softWire.cy.ts (D4 graceful-degrade), which
#                                  is meaningful only on a node where the mfa-factors-webauthn
#                                  bundle is ABSENT (docker-compose.totp-only.yml).
#
# This stack runs under the dedicated Compose project COMPOSE_PROJECT_NAME (see set-env.sh) so it
# never collides with sibling Jahia test harnesses. The cypress service bind-mounts ./ to
# /home/jahians, so results are written straight to ./results on the host.
set -e

source ./set-env.sh

cd "$(dirname "$0")"

HOST_HTTP_PORT="${JAHIA_HTTP_PORT:-8090}"

echo " == Printing the most important environment variables"
echo " JAHIA_IMAGE: ${JAHIA_IMAGE}"
echo " TESTS_IMAGE: ${TESTS_IMAGE}"
echo " MODULE_ID: ${MODULE_ID}"
echo " JAHIA_URL: ${JAHIA_URL}"
echo " COMPOSE_PROJECT_NAME: ${COMPOSE_PROJECT_NAME}"

cleanup() {
  echo "== Dumping service logs =="
  docker compose logs jahia > ./artifacts/jahia.log 2>&1 || true
  docker compose logs smtp-server > ./artifacts/smtp-server.log 2>&1 || true
}
trap cleanup EXIT

wait_ready() {
  echo "== Waiting for Jahia to be ready (max 10 min) on host port ${HOST_HTTP_PORT} =="
  for i in $(seq 1 120); do
    if curl -sf -u "root:${SUPER_USER_PASSWORD}" "http://localhost:${HOST_HTTP_PORT}/modules/graphql" \
          -H "Content-Type: application/json" \
          -d '{"query":"{jcr{nodeByPath(path:\"/\"){uuid}}}"}' >/dev/null 2>&1; then
      echo "Jahia is ready (after ${i} attempts)"
      return 0
    fi
    echo "  ...waiting (${i}/120)"
    sleep 5
  done
  echo "ERROR: Jahia did not become ready in time"
  return 1
}

provision() {
  # $1 = artifacts dir holding the .tgz JS modules for this phase
  local jars_dir="$1"

  echo "== Provisioning extra setup (smtp settings) =="
  curl -sf -u "root:${SUPER_USER_PASSWORD}" \
    -F "script=@assets/setup-smtp-server.groovy" \
    "http://localhost:${HOST_HTTP_PORT}/modules/tools/groovyConsole.jsp" >/dev/null 2>&1 || true

  # api-security defaults to security.profile=default, which blocks GraphQL API calls from
  # non-privileged (non-root) users. The MFA admin-gate NEGATIVE specs authenticate as a regular
  # (non site-admin) user and must reach the resolvers so the module's OWN requireSiteAdmin gate
  # is what denies them. security.profile=open (disposable test setup) lets those calls through;
  # the MFA gates still deny as designed.
  echo "== Provisioning security profile (open) via the provisioning API =="
  curl -s -u "root:${SUPER_USER_PASSWORD}" \
    -F "script=@assets/provisioning.yml;type=text/yaml" \
    "http://localhost:${HOST_HTTP_PORT}/modules/api/provisioning"
  echo

  # The /var/jahia/modules hot-deploy folder only installs OSGi .jar bundles, NOT npm .tgz JS-SDK
  # packages, so the .tgz modules are installed here via a multipart provisioning upload.
  echo "== Installing JS-SDK (.tgz) modules from ${jars_dir} via the provisioning API =="
  local TGZ_LIST
  TGZ_LIST=$(cd "${jars_dir}" && ls -1 *.tgz 2>/dev/null)
  if [[ -n "${TGZ_LIST}" ]]; then
    local bundle_json=""
    local file_args=()
    for tgz in ${TGZ_LIST}; do
      bundle_json="${bundle_json:+${bundle_json},}\"${tgz}\""
      file_args+=( -F "file=@${jars_dir}/${tgz}" )
    done
    local script="[{\"installBundle\":[${bundle_json}],\"autoStart\":true}]"
    echo "  script: ${script}"
    curl -s -u "root:${SUPER_USER_PASSWORD}" \
      -F "script=${script};type=application/json" \
      "${file_args[@]}" \
      "http://localhost:${HOST_HTTP_PORT}/modules/api/provisioning"
    echo
  fi
  echo "== Waiting for the JS modules to register their views =="
  sleep 25
}

echo "== Ensuring a clean slate for THIS project only =="
# Scoped to COMPOSE_PROJECT_NAME — never touches other projects' stacks.
docker compose down --remove-orphans -v >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------------------------
# Phase 1 — all-factors stack: the whole suite EXCEPT the D4 soft-wire spec.
# ---------------------------------------------------------------------------------------------
echo "== Phase 1: starting the all-factors stack =="
docker compose up -d jahia smtp-server
wait_ready
provision "artifacts/jars"

PHASE1_SPECS=$(cd cypress/e2e && ls -1 *.cy.ts | grep -v '^ui.webauthn.softWire.cy.ts$' | sed 's#^#cypress/e2e/#' | paste -sd,)
echo "== Running Cypress suite (phase 1, all-factors) =="
set +e
docker compose run --rm \
  -e CYPRESS_baseUrl="http://jahia:8080" \
  -e MAILPIT_URL="http://smtp-server:8025" \
  cypress \
  bash -lc "cd /home/jahians && yarn install && yarn cypress run --browser chrome --spec '${PHASE1_SPECS}'"
PHASE1_EXIT=$?
set -e
echo "== Phase 1 finished with exit code ${PHASE1_EXIT} =="

# ---------------------------------------------------------------------------------------------
# Phase 2 — TOTP-only stack (mfa-factors-webauthn bundle ABSENT): the D4 soft-wire spec only.
# NOTE: --no-deps AND both -f compose files are REQUIRED on the cypress `run`; otherwise Compose
# recreates jahia back to the base (all-factors) volume and destroys the degrade scenario.
# ---------------------------------------------------------------------------------------------
echo "== Phase 2: recreating jahia on the TOTP-only stack (D4 graceful-degrade) =="
docker compose -f docker-compose.yml -f docker-compose.totp-only.yml up -d --force-recreate jahia
wait_ready
provision "artifacts/jars-totp-only"

echo "== Running Cypress suite (phase 2, D4 soft-wire, --no-deps) =="
set +e
docker compose -f docker-compose.yml -f docker-compose.totp-only.yml run --rm --no-deps \
  -e CYPRESS_baseUrl="http://jahia:8080" \
  -e MAILPIT_URL="http://smtp-server:8025" \
  cypress \
  bash -lc "cd /home/jahians && yarn install && yarn cypress run --browser chrome --spec cypress/e2e/ui.webauthn.softWire.cy.ts"
PHASE2_EXIT=$?
set -e
echo "== Phase 2 finished with exit code ${PHASE2_EXIT} =="

echo "== Results were written directly to ./results (bind mount); see ./results/reports =="
echo "== Phase 1 exit=${PHASE1_EXIT}, Phase 2 (D4) exit=${PHASE2_EXIT} =="
if [[ ${PHASE1_EXIT} -eq 0 && ${PHASE2_EXIT} -eq 0 ]]; then
  echo "== Cypress finished with exit code 0 =="
  exit 0
fi
echo "== Cypress finished with a non-zero exit code =="
exit 1
