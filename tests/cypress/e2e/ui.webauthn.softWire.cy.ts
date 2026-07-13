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

    it('renders the TOTP section and degrades gracefully with WebAuthn absent', () => {
        cy.login(username, password);
        cy.visit(getMfaSettingsPageURL(SITE_KEY));

        // The panel hydrates and shows TOTP self-service — no crash on the missing mfaWebauthn type.
        cy.get('[data-testid="mfa-totp-section"]', {timeout: 30000}).should('be.visible');

        // The WebAuthn/passkey section must be absent (soft-wired off) rather than an error state.
        cy.get('[data-testid="mfa-webauthn-section"]').should('not.exist');
        cy.get('[data-testid="mfa-settings-error"]').should('not.exist');
    });
});
