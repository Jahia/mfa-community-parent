/**
 * D4 — login-ui soft-wires WebAuthn (graceful degrade).
 *
 * login-ui's module-dependencies lists only mfa-factors-totp; WebAuthn is driven purely through
 * runtime GraphQL. So on a node where the mfa-factors-webauthn bundle is NOT installed, the
 * self-service MFA settings panel (and the sign-in flow) must:
 *   - render the TOTP section normally;
 *   - NOT throw / white-screen on the absent mfaWebauthn GraphQL type;
 *   - omit (or grey out) the passkey/WebAuthn section rather than error.
 *
 * REQUIRES the TOTP-only node: run with docker-compose.totp-only.yml (see that file), whose
 * auto-deploy dir contains extensions + totp + login-ui but NOT webauthn. On the standard
 * (all-factors) stack this spec is not meaningful and Stage 6 excludes it from that run.
 */
import {deleteSite, deleteUser, jfaker} from '@jahia/cypress';
import {createSiteWithMfaSettingsPage, createUserForMFA, getMfaSettingsPageURL} from './utils';

const SITE_KEY = 'sample-softwire-totp-only';

describe('login-ui WebAuthn soft-wire — TOTP-only node (UI)', () => {
    let username: string;
    let password: string;

    before(() => {
        createSiteWithMfaSettingsPage(SITE_KEY);
    });

    after(() => {
        try { deleteSite(SITE_KEY); } catch (_e) { /* ignore */ }
    });

    beforeEach(() => {
        username = jfaker.internet.username();
        password = jfaker.internet.password();
        createUserForMFA(username, password, jfaker.internet.email());
    });

    afterEach(() => {
        cy.logout();
        try { deleteUser(username); } catch (_e) { /* ignore */ }
    });

    it('keeps the settings panel usable (TOTP works, no white-screen) with WebAuthn absent', () => {
        cy.login(username, password);
        cy.visit(getMfaSettingsPageURL(SITE_KEY));

        // Core graceful-degrade invariant (the value of D4): the panel hydrates and the TOTP
        // self-service section is usable even though the mfaWebauthn GraphQL type does not exist on
        // this node — no crash, no white-screen, and the user is NOT stuck at the sign-in prompt.
        cy.get('[data-testid="mfa-totp-section"]', {timeout: 30000}).should('be.visible');
        cy.get('[data-testid="mfa-settings-signin"]').should('not.exist');
        cy.get('[data-testid="mfa-totp-enable"], [data-testid="mfa-totp-status"]').should('exist');

        // REGRESSION (D4 soft-wire implemented in Stage 7): with the webauthn bundle absent,
        // webauthnStatus() sees the mfaWebauthn GraphQL type missing from the schema (the query fails
        // validation, so no `data` is returned) and reports "unavailable"; WebauthnSection then
        // returns null. The section — and therefore its error banner and the non-functional "add
        // passkey" button — must be omitted entirely, not merely hidden behind an error.
        cy.get('[data-testid="mfa-webauthn-section"]').should('not.exist');
        cy.get('[data-testid="mfa-webauthn-error"]').should('not.exist');
        cy.get('[data-testid="mfa-webauthn-add"]').should('not.exist');
    });
});
