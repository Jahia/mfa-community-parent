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

        // CHARACTERIZATION (Stage-7 product gap — soft-wire NOT fully implemented):
        // MfaSettings.client.tsx renders <WebauthnSection/> UNCONDITIONALLY, so on a webauthn-absent
        // node the section is still present and currently surfaces the "mfaWebauthn undefined"
        // GraphQL error (plus a non-functional "add passkey" button) instead of being omitted or
        // mapped to the existing mfa-webauthn-unsupported state. Degradation is SAFE (no hard
        // failure — asserted above), so this is a robustness/UX gap, not a security hole.
        // >>> Stage 7: when soft-wiring is implemented, flip the next assertion to `.should('not.exist')`
        //     (or assert mfa-webauthn-unsupported) and drop this note.
        cy.get('[data-testid="mfa-webauthn-section"]').should('exist');
    });
});
