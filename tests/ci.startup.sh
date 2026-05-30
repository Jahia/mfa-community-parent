#!/bin/bash
#
# Bring up Jahia + Cypress + smtp-server, wait for Jahia to be ready, run the
# Cypress suite from inside the cypress container, capture exit code, tear down.
#
# This stack runs under the dedicated Compose project COMPOSE_PROJECT_NAME
# (see set-env.sh) so it never collides with sibling Jahia test harnesses.
# The cypress service bind-mounts ./ to /home/jahians, so results are written
# straight to ./results on the host — no `docker cp` is needed.
set -e

source ./set-env.sh

cd "$(dirname "$0")"

HOST_HTTP_PORT="${JAHIA_HTTP_PORT:-8090}"

echo " == Printing the most important environment variables"
echo " JAHIA_IMAGE: ${JAHIA_IMAGE}"
echo " TESTS_IMAGE: ${TESTS_IMAGE}"
echo " MODULE_ID: ${MODULE_ID}"
echo " JAHIA_URL: ${JAHIA_URL}"
echo " SUPER_USER_PASSWORD: ${SUPER_USER_PASSWORD}"

cleanup() {
  echo "== Tearing down compose stack =="
  docker compose logs jahia > ./artifacts/jahia.log 2>&1 || true
  docker compose logs smtp-server > ./artifacts/smtp-server.log 2>&1 || true
  # NOTE: we leave the cypress container around briefly so the user can `docker cp`
  # the results. The compose `down` is run by the next `ci.build.sh` invocation, or
  # the caller can run it manually.
}
trap cleanup EXIT

echo "== Ensuring a clean slate for THIS project only =="
# Scoped to COMPOSE_PROJECT_NAME — never touches other projects' stacks.
docker compose down --remove-orphans -v >/dev/null 2>&1 || true

echo "== Starting services =="
docker compose up -d jahia smtp-server

echo "== Waiting for Jahia to be ready (max 10 min) on host port ${HOST_HTTP_PORT} =="
for i in $(seq 1 120); do
  if curl -sf -u "root:${SUPER_USER_PASSWORD}" "http://localhost:${HOST_HTTP_PORT}/modules/graphql" \
        -H "Content-Type: application/json" \
        -d '{"query":"{jcr{nodeByPath(path:\"/\"){uuid}}}"}' >/dev/null 2>&1; then
    echo "Jahia is ready (after ${i} attempts)"
    break
  fi
  echo "  ...waiting (${i}/120)"
  sleep 5
done

echo "== Provisioning extra setup (smtp settings) =="
curl -sf -u "root:${SUPER_USER_PASSWORD}" \
  -F "script=@assets/setup-smtp-server.groovy" \
  "http://localhost:${HOST_HTTP_PORT}/modules/tools/groovyConsole.jsp" >/dev/null 2>&1 || true

echo "== Running Cypress suite =="
set +e
docker compose run --rm \
  -e CYPRESS_baseUrl="http://jahia:8080" \
  -e MAILPIT_URL="http://smtp-server:8025" \
  cypress \
  bash -lc "cd /home/jahians && yarn install && yarn e2e:ci"
EXIT_CODE=$?

echo "== Cypress finished with exit code ${EXIT_CODE} =="
echo "== Results were written directly to ./results (bind mount); see ./results/reports =="
exit ${EXIT_CODE}
