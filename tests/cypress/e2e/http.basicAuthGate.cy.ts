/**
 * HTTP-level coverage for the OPT-IN Basic-auth arm of the MFA login gate
 * (MfaLoginGateAuthValve + loginGate.gateBasicAuth, in the mfa-factors-extensions bundle).
 *
 * Jahia's HttpBasicAuthValve authenticates a username/password taken from an
 * `Authorization: Basic` header and never consults MFA factors — so while enforcement is active
 * that header is a second-factor bypass exactly like /cms/login is. The gate can close it, but
 * that shape is NOT confined to one endpoint: it is what every script, CI job, integration and
 * WebDAV client sends, so closing it refuses the whole machine-facing surface at once — the
 * provisioning API that configures this module included. It is therefore opt-in
 * (`loginGate.gateBasicAuth`, default false), and this spec pins BOTH halves of that contract:
 *
 *  - DEFAULT (not armed): a Basic credential still authenticates while enforcement is active.
 *    This is the regression guard. Making it always-on would 403 every integration on the
 *    platform the moment ONE site enforces a factor — including this suite's own GraphQL and
 *    provisioning calls, which authenticate with Basic auth (@jahia/cypress builds its apollo
 *    client with an `Authorization: Basic` header).
 *  - ARMED: the credential is refused with 403 before authentication, on any endpoint, and the
 *    IP whitelist remains the operator's way back in.
 *
 * The unconditional /cms/login form-parameter block is NOT affected by this switch; the last
 * case here pins that, and http.loginGate.cy.ts covers it in full.
 *
 * THE RUNNER MUST BE WHITELISTED FOR THE WHOLE SPEC. This is not a convenience — it is forced by
 * the harness, and it is the clearest demonstration of the blast radius the opt-in guards. Around
 * EVERY test, @jahia/cypress runs global before/beforeEach/afterEach hooks that write a marker into
 * the Jahia log (`jahiaLog.enableSpecsMarker` → `cy.executeGroovy` → a multipart POST to
 * /modules/api/provisioning), authenticated with Basic auth and carrying no headers of ours. Arm
 * the gate without whitelisting this container and those hooks answer 403, so every test in the
 * spec fails in its hooks no matter what it asserts.
 *
 * So the whitelist covers the private ranges the Compose network lives in, and the spec drives the
 * gated/not-gated distinction from the OTHER side: a probe that must be refused presents a
 * non-whitelisted client identity via X-Forwarded-For (which requires the explicit
 * trustForwardedFor opt-in — with the secure default, Tomcat's RemoteIpValve has already rewritten
 * getRemoteAddr() and the gate fails closed, GHSA-4v3g-mcmj-83fp). A probe that must pass simply
 * sends no such header and is seen as the whitelisted container.
 *
 * after() still disarms defensively (failOnStatusCode: false, then a bare retry) so a mid-spec
 * failure can never leave the following specs locked out of the API.
 */
import {createSite, deleteSite} from '@jahia/cypress';
import {editMfaExtensionsConfig, setGlobalEnforcement, setSiteTotpSettings} from './utils';

const SITE_KEY = 'sample-mfa-basic-gate';
const ROOT_USER = 'root';

/** Private ranges — the Compose network the cypress and jahia containers share. */
const WHITELIST_CIDR = '10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16';

/**
 * A client identity OUTSIDE the whitelist (TEST-NET-2). Probes that must be refused present this;
 * probes that must pass send nothing and are seen as the whitelisted container address.
 */
const OUTSIDE_CLIENT = {'X-Forwarded-For': '198.51.100.9'};

const rootPassword = () => Cypress.env('SUPER_USER_PASSWORD') as string;

/** An explicit `Authorization: Basic` value — the exact shape HttpBasicAuthValve consumes. */
const basicAuth = (user: string, pass: string) => `Basic ${btoa(`${user}:${pass}`)}`;

/** `{ currentUser { name } }` — the cheapest probe for "did this credential establish an identity?". */
const graphqlProbe = (headers: Record<string, string>) => cy.request({
    method: 'POST',
    url: '/modules/graphql',
    failOnStatusCode: false,
    headers: {'Content-Type': 'application/json', ...headers},
    body: {query: '{ currentUser { name } }'},
});

/**
 * The authenticated user name a probe reports, or undefined. Deliberately typed loosely: the body
 * is a GraphQL envelope on success and Jahia's HTML error page on a 403, so this is a genuine
 * untyped HTTP boundary.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const identityOf = (response: Cypress.Response<any>): string | undefined =>
    response.body?.data?.currentUser?.name;

/** A provisioning read-back — the endpoint an operator needs to stay reachable. */
const provisioningProbe = (headers: Record<string, string>) => cy.request({
    method: 'POST',
    url: '/modules/api/provisioning',
    failOnStatusCode: false,
    headers: {'Content-Type': 'application/json', ...headers},
    body: [{editConfiguration: 'org.jahia.modules.mfa.extensions', properties: {}}],
});

/** Arm or disarm the Basic-auth gate. Sends no X-Forwarded-For, so it writes as a whitelisted client. */
const setBasicAuthGate = (enabled: boolean) =>
    editMfaExtensionsConfig({'loginGate.gateBasicAuth': String(enabled)});

describe('Basic-auth arm of the MFA gate (loginGate.gateBasicAuth, HTTP)', () => {
    before(() => {
        deleteSite(SITE_KEY);
        createSite(SITE_KEY, {
            locale: 'en',
            languages: 'en',
            templateSet: 'user-password-authentication-template-set-test-module',
            serverName: 'localhost',
        });
        cy.apolloClient({username: ROOT_USER, password: rootPassword()});
        setSiteTotpSettings(SITE_KEY, true);
        // Whitelist this container BEFORE arming anything: @jahia/cypress's per-test log-marker
        // hooks call the provisioning API with Basic auth, so an un-whitelisted runner cannot even
        // get through its own beforeEach once the gate is armed. trustForwardedFor is what lets the
        // probes below present a different client identity through X-Forwarded-For.
        editMfaExtensionsConfig({
            'loginGate.enabled': 'false',
            'loginGate.gateBasicAuth': 'false',
            'loginGate.ipWhitelist': WHITELIST_CIDR,
            'loginGate.trustForwardedFor': 'true',
        });
        setGlobalEnforcement('totp', 0);
    });

    after(() => {
        // Disarm FIRST and defensively — everything below needs a working Basic credential, and a
        // failure earlier in this spec may have left the gate armed.
        cy.request({
            method: 'POST',
            url: '/modules/api/provisioning',
            auth: {user: ROOT_USER, pass: rootPassword()},
            failOnStatusCode: false,
            headers: {'Content-Type': 'application/json'},
            body: [{
                editConfiguration: 'org.jahia.modules.mfa.extensions',
                properties: {'loginGate.gateBasicAuth': 'false'},
            }],
        });
        cy.wait(2000);
        // Belt and braces: the write above is unauthenticated-safe only while the runner is
        // whitelisted, so retry once the gate is (expected to be) off.
        editMfaExtensionsConfig({'loginGate.gateBasicAuth': 'false'});

        setGlobalEnforcement('', 0);
        editMfaExtensionsConfig({
            'loginGate.enabled': 'false',
            'loginGate.ipWhitelist': '',
            'loginGate.trustForwardedFor': 'false',
        });
        cy.apolloClient({username: ROOT_USER, password: rootPassword()});
        setSiteTotpSettings(SITE_KEY, false);
        deleteSite(SITE_KEY);
    });

    // Each case sets the switch it needs rather than inheriting it from the previous one: the
    // state lives on the server, and `retries` re-runs a single test, not the ones before it.

    it('leaves a Basic credential alone by default, even with enrollment enforced', () => {
        // THE REGRESSION GUARD. Enforcement is armed and TOTP is enabled on a site, so the gate is
        // live — but gateBasicAuth is at its shipped default, so every non-interactive client
        // (this suite included) keeps authenticating.
        setBasicAuthGate(false);
        graphqlProbe({Authorization: basicAuth(ROOT_USER, rootPassword()), ...OUTSIDE_CLIENT})
            .then(response => {
                expect(response.status, 'the default must not break machine clients').to.eq(200);
                expect(identityOf(response), 'the Basic credential still authenticates').to.eq(ROOT_USER);
            });
    });

    it('keeps the provisioning API reachable by default', () => {
        // The endpoint that configures this very module. If the default ever flips, an operator who
        // armed enforcement would lose the API needed to revert it.
        setBasicAuthGate(false);
        provisioningProbe({Authorization: basicAuth(ROOT_USER, rootPassword()), ...OUTSIDE_CLIENT})
            .then(response => {
                expect(response.status, 'provisioning must stay reachable at the default').to.not.eq(403);
            });
    });

    it('refuses a Basic credential with 403 once armed', () => {
        setBasicAuthGate(true);
        graphqlProbe({Authorization: basicAuth(ROOT_USER, rootPassword()), ...OUTSIDE_CLIENT})
            .then(response => {
                expect(response.status, 'armed + enforced + not whitelisted').to.eq(403);
                expect(identityOf(response), 'the password must not have authenticated').to.not.eq(ROOT_USER);
            });
    });

    it('refuses it on the provisioning API too — the block is not endpoint-scoped', () => {
        // The operational cost the opt-in exists for: arming the switch takes the configuration API
        // down for Basic-auth callers as well, which is why the whitelist must be verified first.
        setBasicAuthGate(true);
        provisioningProbe({Authorization: basicAuth(ROOT_USER, rootPassword()), ...OUTSIDE_CLIENT})
            .then(response => {
                expect(response.status, 'the valve runs on every endpoint, not just /cms/login').to.eq(403);
            });
    });

    it('still lets a whitelisted client through while armed (the emergency door)', () => {
        // No X-Forwarded-For: the gate sees this container's own (whitelisted) address. This is the
        // operator's way back in — and the only reason the harness survives an armed gate at all.
        setBasicAuthGate(true);
        graphqlProbe({Authorization: basicAuth(ROOT_USER, rootPassword())}).then(response => {
            expect(response.status, 'the whitelist is the operator way back in').to.eq(200);
            expect(identityOf(response)).to.eq(ROOT_USER);
        });
    });

    it('leaves a non-password Authorization scheme alone while armed', () => {
        // A token scheme presents no password and carries its own policy (TokenAuthValve), so the
        // gate must not answer for it. The token is bogus, so the request simply does not
        // authenticate — what matters is that it is not the gate's 403, even from outside the
        // whitelist where a Basic credential would be refused.
        setBasicAuthGate(true);
        graphqlProbe({Authorization: 'Bearer not-a-real-token', ...OUTSIDE_CLIENT}).then(response => {
            expect(response.status, 'a token credential is not this gate business').to.not.eq(403);
            expect(identityOf(response)).to.not.eq(ROOT_USER);
        });
    });

    it('gates the /cms/login form shape regardless of the switch', () => {
        // The form-parameter block is unconditional: the switch only governs the header shape.
        setBasicAuthGate(false);
        cy.request({
            method: 'POST',
            url: '/cms/login',
            form: true,
            failOnStatusCode: false,
            followRedirect: false,
            headers: OUTSIDE_CLIENT,
            body: {site: SITE_KEY, username: 'gate-probe', password: 'irrelevant'},
        }).then(response => {
            expect(response.status, 'the /cms/login block is not opt-in').to.be.oneOf([302, 403]);
        });
    });

    it('restores Basic authentication once disarmed', () => {
        // Reverting the key must take effect live (@Modified) — that hot reload is the documented
        // way back when the whitelist cannot match and only the .cfg on disk can be edited.
        setBasicAuthGate(true);
        setBasicAuthGate(false);
        graphqlProbe({Authorization: basicAuth(ROOT_USER, rootPassword()), ...OUTSIDE_CLIENT})
            .then(response => {
                expect(response.status, 'reverting the switch must restore machine access').to.eq(200);
                expect(identityOf(response)).to.eq(ROOT_USER);
            });
    });
});
