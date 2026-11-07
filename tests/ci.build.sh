#!/bin/bash
#
# Stage all module JARs that Jahia needs to boot with TOTP support into
# ./artifacts/jars/. The docker-compose volume mount of that dir into the
# Jahia container's auto-deploy directory makes them available at startup.
#
# Bundles staged:
#   - UPA api JAR              (from ${UPA_DIR}/api/target/)
#   - UPA UI JS module (.tgz)  (from ${UPA_DIR}/ui/target/)
#   - UPA template-set test    (from ${UPA_DIR}/test-modules/template-set/target/)
#                              — needed because the login-flow specs build a site with this templateSet
#   - MFA extensions JAR       (from ../extensions/target/)
#   - TOTP factor JAR          (from ../target/)
#   - WebAuthn factor JAR      (from ../webauthn/target/)
#   - TOTP login-ui tgz        (from ../login-ui/target/)
set -e

source ./set-env.sh

cd "$(dirname "$0")"
ARTIFACTS_DIR="$(pwd)/artifacts/jars"
mkdir -p "${ARTIFACTS_DIR}"
rm -f "${ARTIFACTS_DIR}"/*.jar "${ARTIFACTS_DIR}"/*.tgz

# UPA must be built at the version the bundles compile against (<upa.version> in the extensions,
# totp and webauthn poms):
# the UPA api is a jahia-depends of every MFA bundle, so the e2e stack must run that same UPA.
# UPA_DIR defaults to a sibling checkout; point it elsewhere (e.g. a worktree of the matching UPA
# tag) when that checkout is on another version.
UPA_DIR="${UPA_DIR:-../../user-password-authentication}"
UPA_VERSIONS="$(sed -n 's:.*<upa.version>\(.*\)</upa.version>.*:\1:p' ../extensions/pom.xml ../totp/pom.xml ../webauthn/pom.xml | sort -u)"
if [[ -z "${UPA_VERSIONS}" || "$(wc -l <<< "${UPA_VERSIONS}")" -ne 1 ]]; then
  echo "ERROR: expected one <upa.version> across the extensions, totp and webauthn poms, got: ${UPA_VERSIONS:-none}"
  exit 1
fi
UPA_VERSION="${UPA_VERSIONS}"
echo "== UPA ${UPA_VERSION} expected under ${UPA_DIR} =="
UPA_API_DIR="${UPA_DIR}/api/target"
UPA_UI_DIR="${UPA_DIR}/ui/target"
UPA_TEMPLATE_SET_DIR="${UPA_DIR}/test-modules/template-set/target"
EXTENSIONS_TARGET_DIR="../extensions/target"
TOTP_TARGET_DIR="../totp/target"
WEBAUTHN_TARGET_DIR="../webauthn/target"
TOTP_LOGIN_UI_DIR="../login-ui/target"

echo "== Staging UPA api JAR =="
UPA_API_JAR=$(ls -1 "${UPA_API_DIR}"/user-password-authentication-api-"${UPA_VERSION}".jar 2>/dev/null | grep -v sources | grep -v javadoc | head -n1 || true)
if [[ -z "${UPA_API_JAR}" ]]; then
  echo "ERROR: Could not find UPA api ${UPA_VERSION} JAR under ${UPA_API_DIR}. Build UPA ${UPA_VERSION} first (mvn package)."
  exit 1
fi
cp "${UPA_API_JAR}" "${ARTIFACTS_DIR}/"
echo "  staged: $(basename "${UPA_API_JAR}")"

echo "== Staging UPA UI tgz =="
UPA_UI_TGZ=$(ls -1 "${UPA_UI_DIR}"/user-password-authentication-ui-"${UPA_VERSION}".tgz 2>/dev/null | head -n1 || true)
if [[ -z "${UPA_UI_TGZ}" ]]; then
  echo "ERROR: Could not find UPA UI ${UPA_VERSION} tgz under ${UPA_UI_DIR}. Build UPA ${UPA_VERSION} UI first."
  exit 1
fi
cp "${UPA_UI_TGZ}" "${ARTIFACTS_DIR}/"
echo "  staged: $(basename "${UPA_UI_TGZ}")"

echo "== Staging MFA extensions JAR =="
EXTENSIONS_JAR=$(ls -1 "${EXTENSIONS_TARGET_DIR}"/mfa-factors-extensions-*.jar 2>/dev/null | grep -v sources | grep -v javadoc | head -n1 || true)
if [[ -z "${EXTENSIONS_JAR}" ]]; then
  echo "ERROR: Could not find MFA extensions JAR under ${EXTENSIONS_TARGET_DIR}. Run 'mvn package' on mfa-factors-extensions first."
  exit 1
fi
cp "${EXTENSIONS_JAR}" "${ARTIFACTS_DIR}/"
echo "  staged: $(basename "${EXTENSIONS_JAR}")"

echo "== Staging TOTP factor JAR =="
TOTP_JAR=$(ls -1 "${TOTP_TARGET_DIR}"/mfa-factors-totp-*.jar 2>/dev/null | grep -v sources | grep -v javadoc | head -n1 || true)
if [[ -z "${TOTP_JAR}" ]]; then
  echo "ERROR: Could not find TOTP factor JAR under ${TOTP_TARGET_DIR}. Run 'mvn package' on mfa-factors-totp first."
  exit 1
fi
cp "${TOTP_JAR}" "${ARTIFACTS_DIR}/"
echo "  staged: $(basename "${TOTP_JAR}")"

echo "== Staging WebAuthn factor JAR =="
WEBAUTHN_JAR=$(ls -1 "${WEBAUTHN_TARGET_DIR}"/mfa-factors-webauthn-*.jar 2>/dev/null | grep -v sources | grep -v javadoc | head -n1 || true)
if [[ -z "${WEBAUTHN_JAR}" ]]; then
  echo "ERROR: Could not find WebAuthn factor JAR under ${WEBAUTHN_TARGET_DIR}. Run 'mvn package' on mfa-factors-webauthn first."
  exit 1
fi
cp "${WEBAUTHN_JAR}" "${ARTIFACTS_DIR}/"
echo "  staged: $(basename "${WEBAUTHN_JAR}")"

echo "== Staging UPA template-set test module JAR =="
UPA_TEMPLATE_SET_JAR=$(ls -1 "${UPA_TEMPLATE_SET_DIR}"/user-password-authentication-template-set-test-module-"${UPA_VERSION}".jar 2>/dev/null | grep -v sources | grep -v javadoc | head -n1 || true)
if [[ -z "${UPA_TEMPLATE_SET_JAR}" ]]; then
  echo "ERROR: Could not find UPA template-set test ${UPA_VERSION} JAR under ${UPA_TEMPLATE_SET_DIR}."
  echo "       Build it via: mvn -f ${UPA_TEMPLATE_SET_DIR}/../pom.xml package"
  exit 1
fi
cp "${UPA_TEMPLATE_SET_JAR}" "${ARTIFACTS_DIR}/"
echo "  staged: $(basename "${UPA_TEMPLATE_SET_JAR}")"

echo "== Staging TOTP login-ui tgz =="
TOTP_LOGIN_UI_TGZ=$(ls -1 "${TOTP_LOGIN_UI_DIR}"/mfa-factors-login-ui-*.tgz 2>/dev/null | head -n1 || true)
if [[ -z "${TOTP_LOGIN_UI_TGZ}" ]]; then
  echo "ERROR: Could not find TOTP login-ui tgz under ${TOTP_LOGIN_UI_DIR}."
  echo "       Build it via: mvn -f ../login-ui/pom.xml package"
  exit 1
fi
cp "${TOTP_LOGIN_UI_TGZ}" "${ARTIFACTS_DIR}/"
echo "  staged: $(basename "${TOTP_LOGIN_UI_TGZ}")"

# Stage a TOTP-only artifact set (everything EXCEPT the webauthn factor) for the D4 graceful-degrade
# spec (ui.webauthn.softWire.cy.ts), consumed by docker-compose.totp-only.yml.
TOTP_ONLY_DIR="$(pwd)/artifacts/jars-totp-only"
echo "== Staging TOTP-only artifact set (no webauthn) =="
mkdir -p "${TOTP_ONLY_DIR}"
rm -f "${TOTP_ONLY_DIR}"/*.jar "${TOTP_ONLY_DIR}"/*.tgz
for f in "${ARTIFACTS_DIR}"/*; do
  case "$(basename "$f")" in
    mfa-factors-webauthn-*) : ;; # skip webauthn on the TOTP-only node
    *) cp "$f" "${TOTP_ONLY_DIR}/" ;;
  esac
done
echo "  staged (totp-only): $(ls -1 "${TOTP_ONLY_DIR}" | tr '\n' ' ')"

echo "== Building Cypress test image =="
# We do NOT build a custom image; we use the official cypress/included one. Pull it now
# so docker-compose up doesn't wait on first run.
docker pull "${TESTS_IMAGE}" || true

echo "== Done. Staged artifacts:"
ls -la "${ARTIFACTS_DIR}"
