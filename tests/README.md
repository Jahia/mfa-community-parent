# MFA factors — Cypress test suite

End-to-end tests for the MFA Community modules (the `mfa-factors-*` family: `extensions`, `totp`,
`webauthn`, `login-ui`) on top of UPA. The suite is fully self-contained and runs against a Jahia
instance booted from a Docker image with the UPA bundles and the MFA modules pre-installed.

## Prerequisites

1. Docker (with `docker compose`) installed and running.
2. The UPA module has been built locally (at the version the reactor pins — `0.2.0`, checked out
   at `../../user-password-authentication`):
   ```
   cd ../../user-password-authentication && mvn -DskipTests package
   ```
   Produces:
   - `user-password-authentication/api/target/user-password-authentication-api-*.jar`
   - `user-password-authentication/ui/target/user-password-authentication-ui-*.tgz`
3. The MFA modules have been built locally:
   ```
   cd ../ && mvn -DskipTests package
   ```
   Produces (note the artifactIds are `mfa-factors-*`):
   - `extensions/target/mfa-factors-extensions-*.jar`
   - `totp/target/mfa-factors-totp-*.jar`
   - `webauthn/target/mfa-factors-webauthn-*.jar`
   - `login-ui/target/mfa-factors-login-ui-*.tgz`

## How to run

```sh
./ci.build.sh        # stages JARs/tgz into artifacts/ for the Jahia container(s)
./ci.startup.sh      # brings up Jahia + smtp + cypress, runs the suite, exits with its code
docker cp "cypress:/home/jahians/results" .   # pull the results
```

`ci.startup.sh` exits with the Cypress suite's exit code, so it can be wired straight into a CI
pipeline. It runs **two phases**:

- **Phase 1 — all-factors stack** (`docker-compose.yml`): extensions + totp + webauthn + login-ui.
  Runs every spec except `ui.webauthn.softWire`.
- **Phase 2 — TOTP-only stack** (`docker-compose.totp-only.yml`): extensions + totp + login-ui,
  **without** the webauthn bundle. Runs only `ui.webauthn.softWire` to prove the login UI
  soft-wires WebAuthn (the section is omitted, not errored) when the factor is absent.

A test-only provisioning step (`assets/provisioning.yml`) sets `security.profile=open` so
**non-root** GraphQL calls reach the MFA resolvers — otherwise Jahia's api-security layer denies
them at the transport level before the module's own `requireSiteAdmin` gate runs. This exercises
the module's gate, it does not weaken it.

## Layout

- `ci.build.sh` — stages bundles into `artifacts/`.
- `ci.startup.sh` — orchestrates the two `docker compose` phases, runs Cypress, exits with the code.
- `docker-compose.yml` — all-factors Jahia + Cypress + Mailpit. `artifacts/` is bind-mounted into
  the Jahia container's auto-deploy directory so the staged bundles install on boot.
- `docker-compose.totp-only.yml` — the webauthn-absent override stack for the soft-wire spec.
- `cypress/e2e/` — spec files (see below).
- `cypress/e2e/utils/totp.ts` — pure-JS RFC 6238 generator (HMAC-SHA1, 30s step, 6 digits).
- `cypress/e2e/utils/webauthn.ts` — CDP virtual-authenticator helpers for the WebAuthn ceremonies.
- `assets/setup-smtp-server.groovy` — wires Mailpit into Jahia's mail settings.
- `assets/provisioning.yml` — the `security.profile=open` test provisioning.

## Specs

**GraphQL**
- `graphQL.totp.enroll` — enrollment happy-path + re-enroll refusal.
- `graphQL.totp.verify` — login with a TOTP code; replay rejection.
- `graphQL.totp.errors` — confirmEnroll without enroll, wrong code, already-enrolled.
- `graphQL.totp.backupCodes` — backup-code single-use + regenerateBackupCodes gating.
- `graphQL.totp.adminPolicy` / `graphQL.webauthn.adminPolicy` — per-site admin gates (positive).
- `graphQL.adminGates.negative` — non-site-admin denied auditEvents / enrollmentReport /
  resetUserMfa / resetUserWebauthn; `siteSettings` public-read succeeds.
- `graphQL.extensions.adminConfig` — global config mutation is server-admin only.

**HTTP**
- `http.loginGate` — the `/cms/login` gate: redirect / 403 modes, whitelist, XFF handling.

**Login / dashboard UI**
- `ui.totp.login` / `ui.totp.loginEnter` / `ui.totp.enrollAtLogin` / `ui.totp.dashboard` — TOTP UI.
- `ui.webauthn.registerAtLogin` — pre-auth passkey registration.
- `ui.webauthn.login` — returning-user assertion-verify login via a CDP virtual authenticator.
- `ui.webauthn.softWire` — TOTP-only node: the WebAuthn section is omitted (soft-wire), TOTP usable.
- `ui.emailFactor` — UPA's `email_code` factor at sign-in (chooser, Mailpit code, drain releases it).
- `ui.loginRedirect` — post-login return-to-target / open-redirect guard.
- `ui.resetRequest` — locked-out user's admin-notification reset request.
- `ui.settings.guest` / `ui.settings.totp` / `ui.settings.webauthn` — self-service settings panel.
- `ui.a11y` — WCAG 2.2 AAA sweep (axe) of the sign-in and self-service surfaces.

**Admin UI**
- `ui.admin.mfaCommunity` / `ui.admin.extensionsConfig` — the MFA Community administration pages.
