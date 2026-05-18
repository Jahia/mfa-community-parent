/**
 * UI tests for the TOTP MFA dashboard page.
 *
 * Exercises the React UI registered by mfa-totp-factor at adminRoute
 * `mfa-totp-factor` (sidebar target `dashboard:99.2`). The route lives at
 * `/jahia/dashboard/mfa-totp-factor`.
 *
 * The test drives the enroll → confirm → backup-codes → disable flow
 * end-to-end through the rendered components, reading the secret from the
 * enrollment dialog and computing the required TOTP code via the same
 * pure-JS helper the GraphQL specs use.
 */
import {jfaker, deleteUser} from '@jahia/cypress';
import {createUserForMFA, totpCode} from './utils';

const DASHBOARD_PATH = '/jahia/dashboard/mfa-totp-factor';

describe('TOTP dashboard UI', () => {
    let usr: string;
    let pwd: string;

    before(() => {
        usr = jfaker.internet.username();
        pwd = jfaker.internet.password();
        createUserForMFA(usr, pwd, jfaker.internet.email());
    });

    after(() => {
        try { deleteUser(usr); } catch (_e) { /* ignore */ }
    });

    beforeEach(() => {
        cy.login(usr, pwd);
        cy.visit(DASHBOARD_PATH);
        // Wait for the status chip to render (proves the StatusQuery roundtrip completed).
        cy.get('[data-testid="mfa-status"]', {timeout: 30000}).should('be.visible');
    });

    it('enrolls, shows backup codes, then disables — full UI flow', () => {
        // 1. Start: chip says "Disabled"
        cy.get('[data-testid="mfa-status"]').should('contain', 'Disabled');

        // 2. Click "Enable" → the EnrollDialog opens with a QR + the Base32 secret.
        cy.get('[data-testid="enable-mfa-btn"]').click();
        cy.get('[data-testid="enroll-qr"]', {timeout: 15000}).should('be.visible');
        cy.get('[data-testid="enroll-secret"]')
            .invoke('text')
            .then(rawSecret => {
                const secret = rawSecret.replace(/\s+/g, '');
                expect(secret, 'displayed secret').to.have.length.greaterThan(10);

                // 3. Compute the current code and submit.
                const code = totpCode(secret);
                cy.get('[data-testid="enroll-code-input"]').type(code);
                cy.get('[data-testid="enroll-confirm-btn"]').click();

                // 4. BackupCodesDialog opens with the freshly generated codes.
                cy.get('[data-testid="backup-codes-list"]', {timeout: 15000})
                    .should('be.visible')
                    .invoke('text')
                    .then(listText => {
                        const codes = listText.trim().split('\n').map(s => s.trim()).filter(Boolean);
                        expect(codes, 'backup codes count').to.have.length.greaterThan(0);
                        codes.forEach(bc => expect(bc).to.have.length.greaterThan(4));
                    });
                cy.get('[data-testid="backup-codes-close-btn"]').click();

                // 5. The status chip now reflects enrollment.
                cy.get('[data-testid="mfa-status"]', {timeout: 15000}).should('contain', 'Enabled');

                // 6. Disable: open the dialog, enter a CURRENT code (use a fresh code in
                //    case the previous one is in the same step and would replay-reject).
                cy.get('[data-testid="disable-mfa-btn"]').click();
                // Wait one second past the current step boundary to avoid replay rejection
                // when the previous code is still within the same 30s window.
                cy.wait(31000);
                const disableCode = totpCode(secret);
                cy.get('[data-testid="code-prompt-input"]').type(disableCode);
                cy.get('[data-testid="code-prompt-accept-btn"]').click();

                // 7. Back to "Disabled".
                cy.get('[data-testid="mfa-status"]', {timeout: 15000}).should('contain', 'Disabled');
                cy.get('[data-testid="enable-mfa-btn"]').should('be.visible');
            });
    });

    it('regenerates backup codes after enrollment', () => {
        // Re-enroll first (this spec is independent).
        cy.get('[data-testid="enable-mfa-btn"]').click();
        cy.get('[data-testid="enroll-secret"]')
            .invoke('text')
            .then(rawSecret => {
                const secret = rawSecret.replace(/\s+/g, '');
                cy.get('[data-testid="enroll-code-input"]').type(totpCode(secret));
                cy.get('[data-testid="enroll-confirm-btn"]').click();

                // Capture the original backup codes set.
                cy.get('[data-testid="backup-codes-list"]', {timeout: 15000})
                    .invoke('text')
                    .then(firstSetRaw => {
                        const firstSet = firstSetRaw.trim();
                        cy.get('[data-testid="backup-codes-close-btn"]').click();

                        // Wait past the 30s window so we don't get a replay rejection.
                        cy.wait(31000);

                        // Open regen dialog, submit a current code.
                        cy.get('[data-testid="regen-backup-btn"]').click();
                        cy.get('[data-testid="code-prompt-input"]').type(totpCode(secret));
                        cy.get('[data-testid="code-prompt-accept-btn"]').click();

                        // New set must be present and differ from the original.
                        cy.get('[data-testid="backup-codes-list"]', {timeout: 15000})
                            .invoke('text')
                            .then(secondSetRaw => {
                                const secondSet = secondSetRaw.trim();
                                expect(secondSet, 'regenerated set is non-empty').to.have.length.greaterThan(0);
                                expect(secondSet, 'regenerated set differs from the original')
                                    .to.not.equal(firstSet);
                            });
                        cy.get('[data-testid="backup-codes-close-btn"]').click();
                    });
            });
    });

    it('rejects a wrong confirm code with the invalidCode error', () => {
        cy.get('[data-testid="enable-mfa-btn"]').click();
        cy.get('[data-testid="enroll-qr"]', {timeout: 15000}).should('be.visible');

        cy.get('[data-testid="enroll-code-input"]').type('000000');
        cy.get('[data-testid="enroll-confirm-btn"]').click();

        cy.get('[data-testid="enroll-error"]', {timeout: 15000})
            .should('be.visible')
            .and('contain', 'Invalid code');
    });
});
