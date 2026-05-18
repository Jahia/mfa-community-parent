#!/bin/bash
#
# Bring up Jahia + Cypress + smtp-server, wait for Jahia to be ready, run the
# Cypress suite from inside the cypress container, capture exit code, tear down.
#
# Test results land in cypress:/home/jahians/results so the user can do:
#   docker cp "cypress:/home/jahians/results" .
set -e

source ./set-env.sh

cd "$(dirname "$0")"

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

echo "== Starting services =="
docker compose up -d jahia smtp-server

echo "== Waiting for Jahia to be ready (max 10 min) =="
for i in $(seq 1 120); do
  if curl -sf -u "root:${SUPER_USER_PASSWORD}" "http://localhost:8080/modules/graphql" \
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
  "http://localhost:8080/modules/tools/groovyConsole.jsp" >/dev/null 2>&1 || true

echo "== Running Cypress suite =="
set +e
docker compose run --rm \
  -e CYPRESS_baseUrl="http://jahia:8080" \
  -e MAILPIT_URL="http://smtp-server:8025" \
  cypress \
  bash -lc "cd /home/jahians && yarn install && yarn e2e:ci"
EXIT_CODE=$?

echo "== Cypress finished with exit code ${EXIT_CODE} =="
echo "== To copy results out: docker cp cypress:/home/jahians/results . =="
exit ${EXIT_CODE}
