/**
 * F25 (e2e half) — WebAuthn LOGIN assertion verify for a RETURNING user.
 *
 * The existing ui.webauthn.registerAtLogin spec exercises inline registration (create) followed by
 * an immediate in-session assertion. What was missing is a pure ASSERTION-VERIFY login: a user who
 * ALREADY owns a passkey signs in on a later visit through prepare -> navigator.credentials.get()
 * -> verify (no registration step). This is the login-time second-factor path and the highest-value
 * WebAuthn coverage gap.
 *
 * webauthn is made the challengeable factor here (mfaEnabledFactors=['webauthn'] +
 * enforcedFactors='webauthn') so the returning user is genuinely challenged with an assertion rather
 * than skipped via pick-one. A CDP virtual authenticator answers the ceremony.
 *
 * REQUIRES a Chromium secure context on http://jahia:8080 (WebAuthn is HTTPS/localhost-only):
 *   ELECTRON_EXTRA_LAUNCH_ARGS=--unsafely-treat-insecure-origin-as-secure=http://jahia:8080
 * The Relying Party is repointed to rpId=jahia for the suite and restored in after().
 *
 * The unit half (origin / RP-ID / challenge rejection with a crafted assertion) lives in
 * WebAuthnAssertionCeremonyTest; the negative cases are hard to force through a virtual
 * authenticator, so they are asserted at unit level, not here.
 */
import {deleteUser, jfaker} from '@jahia/cypress';
import {
    addVirtualAuthenticator,
    createSiteWithTotpLoginPage,
    createUserForMFA,
    deleteTotpLoginSite,
    getTotpLoginPageURL,
    setGlobalEnforcement,
    setSiteWebauthnSettings,
    setUpaEnabledFactors,
    setWebauthnRpId,
} from './utils';

const SITE_KEY = 'sample-webauthn-login';

describe('WebAuthn login assertion verify — returning user (UI)', () => {
    let username: string;
    let password: string;

    before(() => {
        createSiteWithTotpLoginPage(SITE_KEY);
        setSiteWebauthnSettings(SITE_KEY, true);
        setWebauthnRpId('jahia'); // the in-network host the test browser is on
        setUpaEnabledFactors(['webauthn']); // webauthn is the challengeable factor
        setGlobalEnforcement('webauthn', 0);
    });

    after(() => {
        setGlobalEnforcement('', 0);
        setUpaEnabledFactors(['totp']);
        setWebauthnRpId('localhost');
        deleteTotpLoginSite(SITE_KEY);
    });

    beforeEach(() => {
        username = jfaker.internet.username();
        password = jfaker.internet.password();
        createUserForMFA(username, password, jfaker.internet.email());
        cy.logout();
    });

    afterEach(() => {
        try {
            deleteUser(username);
        } catch (_e) {
            // ignore
        }
    });

    it('signs a returning user in with an existing passkey (prepare -> get() -> verify)', () => {
        addVirtualAuthenticator();

        // First visit: register a passkey inline (create + immediate assertion) → signed in.
        cy.visit(getTotpLoginPageURL(SITE_KEY));
        cy.get('[data-testid="login-username"]', {timeout: 30000}).type(username);
        cy.get('[data-testid="login-password"]').type(password);
        cy.get('[data-testid="login-submit"]').click();
        cy.get('[data-testid="enroll-choose-webauthn"]', {timeout: 30000}).click();
        cy.get('[data-testid="enroll-webauthn-register"]', {timeout: 30000}).click();
        cy.location('pathname', {timeout: 30000}).should('not.contain', '/myLoginPage.html');

        // Second visit: the user now OWNS a credential, so no enrollment chooser appears — they are
        // challenged with an ASSERTION. Driving it (get()) and verifying it must sign them in.
        cy.logout();
        cy.visit(getTotpLoginPageURL(SITE_KEY));
        cy.get('[data-testid="login-username"]', {timeout: 30000}).type(username);
        cy.get('[data-testid="login-password"]').type(password);
        cy.get('[data-testid="login-submit"]').click();

        // The pure assertion path: no registration UI, an authenticate button instead.
        cy.get('[data-testid="enroll-choose-webauthn"]').should('not.exist');
        cy.get('[data-testid="webauthn-authenticate"]', {timeout: 30000}).should('be.visible').click();

        // The verified assertion completes the login and leaves the login page.
        cy.location('pathname', {timeout: 30000}).should('not.contain', '/myLoginPage.html');
    });
});
