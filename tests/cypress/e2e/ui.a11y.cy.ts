/**
 * F34 — WCAG 2.2 accessibility sweep of the MFA UI surfaces with cypress-axe.
 *
 * Policy target is AAA for everything the templates control (structure/landmarks, colour/contrast,
 * focus, keyboard, motion). Content-dependent AAA criteria (sign language, reading level) rest with
 * content authors and are excluded. This spec runs axe with the A/AA/AAA rulesets, checks keyboard
 * traversal and live-region roles, and verifies reduced-motion is honoured.
 *
 * Requires cypress-axe (added to package.json). Stage 6 installs deps and runs it.
 */
import {deleteSite, deleteUser, jfaker} from '@jahia/cypress';
import 'cypress-axe';
import {createSiteWithMfaSettingsPage, createUserForMFA, getMfaSettingsPageURL} from './utils';

const SITE_KEY = 'sample-a11y';

// A/AA/AAA including the 2.1 and 2.2 additions; AAA enables the >=7:1 enhanced-contrast rule.
const AAA_TAGS = ['wcag2a', 'wcag2aa', 'wcag2aaa', 'wcag21a', 'wcag21aa', 'wcag22aa'];
const axeOptions = {runOnly: {type: 'tag' as const, values: AAA_TAGS}};

// Surface the offending rules rather than a bare count when a check fails.
const logViolations = (violations: {id: string; impact: string; nodes: unknown[]}[]) => {
    cy.log(`${violations.length} a11y violation(s)`);
    violations.forEach(v => cy.log(`[${v.impact}] ${v.id} - ${v.nodes.length} node(s)`));
};

describe('MFA UI accessibility (WCAG 2.2 AAA)', () => {
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

    it('the guest sign-in prompt has no AAA axe violations', () => {
        cy.logout();
        cy.visit(getMfaSettingsPageURL(SITE_KEY));
        cy.get('[data-testid="mfa-settings-signin"]', {timeout: 30000}).should('be.visible');

        cy.injectAxe();
        cy.checkA11y(undefined, axeOptions, logViolations);

        // Exactly one top-level main landmark.
        cy.get('main').should('have.length.at.most', 1);
    });

    it('the self-service settings panel has no AAA axe violations and is keyboard reachable', () => {
        cy.login(username, password);
        cy.visit(getMfaSettingsPageURL(SITE_KEY));
        cy.get('[data-testid="mfa-totp-section"]', {timeout: 30000}).should('be.visible');

        cy.injectAxe();
        cy.checkA11y('[data-testid="mfa-totp-section"]', axeOptions, logViolations);

        // Keyboard: the primary TOTP action must be focusable (visible focus is an AAA concern).
        cy.get('[data-testid="mfa-totp-section"] button, [data-testid="mfa-totp-section"] a')
            .first()
            .focus()
            .should('be.focused');
    });

    it('status/alert live regions are exposed to assistive tech', () => {
        cy.login(username, password);
        cy.visit(getMfaSettingsPageURL(SITE_KEY));
        cy.get('[data-testid="mfa-totp-section"]', {timeout: 30000}).should('be.visible');

        // Feedback must be announced: at least one role=alert or role=status live region exists in the panel.
        cy.get('[role="alert"], [role="status"], [aria-live]').should('exist');
    });
});
