# AGENTS.md

Notes for AI coding agents (Claude Code, Cursor, etc.) working on this repository.
Keep edits minimal and consistent with the conventions below.

## Project type

Third-party Jahia 8.2 OSGi bundle. It implements the `MfaFactorProvider` SPI exposed by
the [User Password Authentication (UPA)](https://github.com/Jahia/user-password-authentication)
module and contributes a TOTP factor to UPA's MFA pipeline. It is not part of the UPA
repo and is published under groupId `org.jahia.community` (required by Jahia EE's license
check &mdash; do not change it).

The functional spec lives **outside this repository** at
`../SPEC-TOTP.md` (i.e. `SUPPORT/SUPPORT-591/SPEC-TOTP.md`). Keep the implementation in
sync with that document; do not duplicate its contents inside the module.

## Repo layout

```
src/main/java/org/jahia/modules/upa/mfa/totp/
  TotpService.java                 RFC 6238 primitive: HOTP/TOTP generation + verification, Base32, otpauth:// URI.
  TotpFactorProvider.java          UPA MfaFactorProvider SPI implementation (verify entry point used at login).
  TotpUserStore.java               JCR-backed persistence of per-user settings (secret, hashed backup codes, lastUsedCounter).
  TotpEnrollmentState.java         Transient (in-session) secret + TTL while the user is enrolling.
  TotpPreparationResult.java       MFA "preparation" DTO.
  TotpManagementRateLimiter.java   In-memory throttle for management mutations (enroll/confirm/regen/disable).
  BackupCodes.java                 Generates, PBKDF2-hashes, and constant-time-verifies backup codes.
  gql/
    TotpFactorMutation.java        GraphQL mutations: enroll/confirmEnroll/prepare/verify/regenerateBackupCodes/disable.
    TotpFactorMutationExtension.java  @GraphQLTypeExtension that grafts `totp` onto UPA's FactorsMutation.
    TotpEnrollResult / TotpConfirmEnrollResult / TotpBackupCodesResult / TotpPreparation
    ExtensionsAutoDiscovery.java   Registers the @GraphQLTypeExtension with graphql-dxm-provider.
src/main/resources/META-INF/
  definitions.cnd                            JCR node type for the per-user settings node.
  configurations/org.jahia.bundles.api.authorization-mfa-totp-factor.yml  Grants GraphQL types.
src/test/java/...                            JUnit 4 tests.
tests/                                       Cypress / docker-compose E2E harness (mirrors UPA's tests/ structure).
pom.xml                                      Maven bundle build.
```

## Build

```bash
mvn clean install
```

Requires `user-password-authentication-api` (UPA's `api` module) in the local Maven repo
or in Jahia's public Nexus. UPA must be built first when working from a snapshot.

## Tests

- Unit: `mvn test` (JUnit 4).
- E2E: `cd tests && ./ci.build.sh && ./ci.startup.sh`, then
  `docker cp "cypress:/home/jahians/results" .`.

## Key invariants &mdash; do not bypass

- **Replay protection chokepoint:** `TotpUserStore.verifyAndConsumeTotp` is the single
  function that re-reads `lastUsedCounter`, verifies the code, and persists the consumed
  counter in the **same JCR transaction**. Every management mutation that consumes a TOTP
  code routes through this method via `TotpFactorMutation.verifyTotpAndConsume`. Do not
  add a sibling code path that verifies without consuming.
- **Backup codes are PBKDF2-hashed at rest** (`BackupCodes.hash`); never persist or
  compare raw codes. Verification uses `MessageDigest.isEqual` (constant time).
- **Secrets are write-once towards the client:** the Base32 secret and `otpauth://` URI
  leave the server only on the `enroll` response. After `confirmEnroll`, the secret is
  never returned by any API and never logged. Preserve this when adding fields.
- **Constant-time comparisons** for all code/hash comparisons.
- **GroupId `org.jahia.community`** in `pom.xml` is required by Jahia EE license checks.
  Do not move the bundle under `org.jahia.modules`.

## GraphQL wiring

The mutation tree is grafted onto UPA's `FactorsMutation` via the
`@GraphQLTypeExtension` annotation in `TotpFactorMutationExtension`. Discovery happens
through `gql/ExtensionsAutoDiscovery`, registered as an OSGi `@Component` that exposes a
`DXGraphQLExtensionsProvider`. If you add new GraphQL types or mutations, register them
in the same file and grant them in `org.jahia.bundles.api.authorization-mfa-totp-factor.yml`.

## Common pitfalls

- Do **not** override the parent `maven-bundle-plugin` instructions wholesale. The
  bundle's `Import-Package` list must include `${jahia.plugin.projectPackageImport}` and
  the UPA SPI packages (`org.jahia.modules.upa.mfa[.gql]`); extend, do not replace.
- Do **not** add new third-party runtime dependencies without checking they are already
  on the Jahia classpath. Cryptography uses only `java.security` / `javax.crypto`;
  Base32 comes from `commons-codec` which Jahia ships.
- The Cypress suite runs in the **browser context**: do not introduce Node-only APIs
  (e.g. `Buffer.writeBigUInt64BE`) in test helpers. Use `Uint8Array` and `BigInt` math.
- The `enroll(force: true)` path is sensitive (it rotates the second factor). Keep its
  guards: admin OR a valid `currentCode` consumed through the chokepoint.

## Security review

To re-run a security review pass, prompt a fresh agent with something like:

> Review every file under `src/main/java/org/jahia/modules/upa/mfa/totp/` for: replay,
> timing-attack, brute force, secret disclosure, JCR transaction races, logging of
> secrets/codes, and OWASP ASVS controls relevant to MFA. Cross-check against
> `../SECURITY-REVIEW.md`. Output findings as severity/title/file/lines/fix.

See `../SECURITY-REVIEW.md` and `../SECURITY-FIXES.md` for the previous pass.
