/**
 * Site administration navigation: the "MFA Community" group and its four entries.
 *
 * The group is registered (defensively, by whichever factor bundle activates first) at
 * adminRoute key `mfa-community`; children attach via the `administration-sites-mfa-community`
 * target:
 *   1. Extensions                 (mfa-community-extensions — per-site login/logout routing)
 *   2. Authenticator app (TOTP)   (mfa-factors-totp-site-settings)
 *   3. Security keys & passkeys   (mfa-factors-webauthn-site-settings)
 *   4. Audit & reporting          (mfa-community-audit — composes both factors' audit sections)
 *
 * Routes render at /jahia/administration/<siteKey>/<routeKey>.
 */
import {createSite, deleteSite} from '@jahia/cypress';

const SITE_KEY = 'sample-mfa-admin';
const ADMIN = `/jahia/administration/${SITE_KEY}`;

describe('MFA Community site administration navigation', () => {
    before(() => {
        deleteSite(SITE_KEY);
        createSite(SITE_KEY, {
            locale: 'en',
            languages: 'en',
            templateSet: 'user-password-authentication-template-set-test-module',
            serverName: 'localhost'
        });
    });

    after(() => {
        deleteSite(SITE_KEY);
    });

    beforeEach(() => {
        cy.login(); // Root: has siteAdminAccess everywhere.
    });

    it('shows the MFA Community group with its four entries', () => {
        // Visiting a child route auto-opens its ancestors in the sites accordion (the admin
        // shell computes defaultOpenedItems by walking parent targets), so the group and all
        // of its entries must be visible in the navigation tree.
        cy.visit(`${ADMIN}/mfa-community-extensions`);
        cy.contains('MFA Community', {timeout: 30000}).should('be.visible');
        cy.contains('Extensions').should('be.visible');
        cy.contains('Authenticator app (TOTP)').should('be.visible');
        cy.contains('Security keys & passkeys').should('be.visible');
        cy.contains('Audit & reporting').should('be.visible');
    });

    it('Extensions hosts the per-site login/logout URL fields', () => {
        cy.visit(`${ADMIN}/mfa-community-extensions`);
        cy.get('[data-testid="site-login-url-input"]', {timeout: 30000}).should('be.visible');
        cy.get('[data-testid="site-logout-url-input"]').should('be.visible');
        cy.get('[data-testid="extensions-settings-save-btn"]').should('be.visible');
    });

    it('Authenticator app (TOTP) keeps the policy fields but no longer the URL fields', () => {
        cy.visit(`${ADMIN}/mfa-factors-totp-site-settings`);
        cy.get('[data-testid="site-enabled-toggle"]', {timeout: 30000}).should('exist');
        cy.get('[data-testid="site-login-url-input"]').should('not.exist');
        cy.get('[data-testid="audit-report-section"]').should('not.exist');
    });

    it('Security keys & passkeys renders the WebAuthn policy page', () => {
        cy.visit(`${ADMIN}/mfa-factors-webauthn-site-settings`);
        cy.get('[data-testid="webauthn-site-enabled-toggle"]', {timeout: 30000}).should('exist');
        cy.get('[data-testid="audit-report-section"]').should('not.exist');
    });

    it('Audit & reporting composes the sections of both installed factors', () => {
        cy.visit(`${ADMIN}/mfa-community-audit`);
        cy.get('[data-testid="audit-report-section"]', {timeout: 30000}).should('have.length', 2);
        cy.get('[data-testid="load-audit-btn"]').should('have.length', 2);
        // Each section identifies its factor: marker attribute + a factor-specific heading.
        cy.get('[data-testid="audit-report-section"][data-factor="totp"]')
            .should('contain.text', 'Authenticator app (TOTP)');
        cy.get('[data-testid="audit-report-section"][data-factor="webauthn"]')
            .should('contain.text', 'Security keys & passkeys (WebAuthn)');
    });
});
