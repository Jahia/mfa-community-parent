/**
 * Negative admin-gate coverage for BOTH factors (consolidates gap items D5, F18, F19, F29).
 *
 * The invariant under test (verified in source, MfaAdminAccess.requireSiteAdmin +
 * TotpFactorQuery/WebAuthnFactorQuery):
 *   - siteSettings(siteKey) is INTENTIONALLY public-read (no admin gate) so the login UI can decide
 *     whether to render a factor step — it exposes only enabled / enabledGroups / login+logout URLs,
 *     never any secret (D5, positive half);
 *   - auditEvents(siteKey) and enrollmentReport(siteKey) ARE gated by requireSiteAdmin — a non
 *     site-admin caller must be denied (D5 negative half; F19 totp, F29 webauthn);
 *   - resetUserMfa(userId, siteKey) is gated too — a non site-admin caller must be denied (F18).
 *
 * Existing specs cover only the setSiteSettings denial; these it-blocks close the remaining
 * negative gates. Positive (admin) round-trips live in graphQL.{totp,webauthn}.adminPolicy.cy.ts.
 */
import {createSite, createUser, deleteSite, deleteUser, jfaker} from '@jahia/cypress';
import gql from 'graphql-tag';
import {firstErrorMessage} from './utils';

const SITE_KEY = 'sample-admin-gates';
const ROOT = {username: 'root', password: Cypress.env('SUPER_USER_PASSWORD') as string};
const DENIED = /permission_denied|not_authenticated/;

const enableTotp = () => cy.apollo({
    mutation: gql`mutation($s: String!) { upa { mfaFactors { totp {
        setSiteSettings(siteKey: $s, enabled: true) { enabled } } } } }`,
    variables: {s: SITE_KEY},
    errorPolicy: 'all'
});

const enableWebauthn = () => cy.apollo({
    mutation: gql`mutation($s: String!) { upa { mfaFactors { webauthn {
        setSiteSettings(siteKey: $s, enabled: true) { enabled } } } } }`,
    variables: {s: SITE_KEY},
    errorPolicy: 'all'
});

describe('MFA admin gates — negative (GraphQL)', () => {
    let userId: string;
    let password: string;

    before(() => {
        deleteSite(SITE_KEY);
        createSite(SITE_KEY, {
            locale: 'en',
            languages: 'en',
            templateSet: 'user-password-authentication-template-set-test-module',
            serverName: 'localhost'
        });
        cy.apolloClient(ROOT);
        enableTotp();
        enableWebauthn();
    });

    after(() => {
        cy.apolloClient(ROOT);
        if (userId) {
            try { deleteUser(userId); } catch (e) { /* ignore */ }
        }
        try { deleteSite(SITE_KEY); } catch (e) { /* ignore */ }
    });

    beforeEach(() => {
        // A freshly-created regular user is authenticated but is NOT a site admin.
        userId = jfaker.internet.username();
        password = jfaker.internet.password();
        createUser(userId, password);
        cy.apolloClient({username: userId, password});
    });

    afterEach(() => {
        cy.apolloClient(ROOT);
        if (userId) {
            try { deleteUser(userId); } catch (e) { /* ignore */ }
        }
        userId = undefined;
    });

    // --- TOTP -------------------------------------------------------------------------------

    it('D5: totp siteSettings is public-read for a non site-admin (no secrets exposed)', () => {
        cy.apollo({
            query: gql`query($s: String!) { mfaTotp { siteSettings(siteKey: $s) {
                enabled enabledGroups loginUrl logoutUrl } } }`,
            variables: {s: SITE_KEY},
            fetchPolicy: 'no-cache',
            errorPolicy: 'all'
        }).then(res => {
            expect(firstErrorMessage(res), 'public-read siteSettings must NOT be denied').to.be.undefined;
            expect(res?.data?.mfaTotp?.siteSettings?.enabled, 'reflects the enabled flag').to.eq(true);
        });
    });

    it('F19: totp auditEvents is denied to a non site-admin', () => {
        cy.apollo({
            query: gql`query($s: String!) { mfaTotp { auditEvents(siteKey: $s, limit: 10) { eventType } } }`,
            variables: {s: SITE_KEY},
            fetchPolicy: 'no-cache',
            errorPolicy: 'all'
        }).then(res => {
            expect(firstErrorMessage(res), 'auditEvents must be requireSiteAdmin-gated').to.match(DENIED);
        });
    });

    it('F19: totp enrollmentReport is denied to a non site-admin', () => {
        cy.apollo({
            query: gql`query($s: String!) { mfaTotp { enrollmentReport(siteKey: $s, limit: 10) { totalUsers } } }`,
            variables: {s: SITE_KEY},
            fetchPolicy: 'no-cache',
            errorPolicy: 'all'
        }).then(res => {
            expect(firstErrorMessage(res), 'enrollmentReport must be requireSiteAdmin-gated').to.match(DENIED);
        });
    });

    it('F18: totp resetUserMfa is denied to a non site-admin', () => {
        cy.apollo({
            mutation: gql`mutation($u: String!, $s: String!) { upa { mfaFactors { totp {
                resetUserMfa(userId: $u, siteKey: $s) } } } }`,
            variables: {u: 'root', s: SITE_KEY},
            errorPolicy: 'all'
        }).then(res => {
            expect(firstErrorMessage(res), 'resetUserMfa must be requireSiteAdmin-gated').to.match(DENIED);
        });
    });

    // --- WebAuthn ---------------------------------------------------------------------------

    it('D5: webauthn siteSettings is public-read for a non site-admin (no secrets exposed)', () => {
        cy.apollo({
            query: gql`query($s: String!) { mfaWebauthn { siteSettings(siteKey: $s) {
                enabled enabledGroups } } }`,
            variables: {s: SITE_KEY},
            fetchPolicy: 'no-cache',
            errorPolicy: 'all'
        }).then(res => {
            expect(firstErrorMessage(res), 'public-read siteSettings must NOT be denied').to.be.undefined;
            expect(res?.data?.mfaWebauthn?.siteSettings?.enabled, 'reflects the enabled flag').to.eq(true);
        });
    });

    it('F29: webauthn auditEvents is denied to a non site-admin', () => {
        cy.apollo({
            query: gql`query($s: String!) { mfaWebauthn { auditEvents(siteKey: $s, limit: 10) { eventType } } }`,
            variables: {s: SITE_KEY},
            fetchPolicy: 'no-cache',
            errorPolicy: 'all'
        }).then(res => {
            expect(firstErrorMessage(res), 'auditEvents must be requireSiteAdmin-gated').to.match(DENIED);
        });
    });

    it('F29: webauthn enrollmentReport is denied to a non site-admin', () => {
        cy.apollo({
            query: gql`query($s: String!) { mfaWebauthn { enrollmentReport(siteKey: $s, limit: 10) { totalUsers } } }`,
            variables: {s: SITE_KEY},
            fetchPolicy: 'no-cache',
            errorPolicy: 'all'
        }).then(res => {
            expect(firstErrorMessage(res), 'enrollmentReport must be requireSiteAdmin-gated').to.match(DENIED);
        });
    });

    it('F29: webauthn resetUserWebauthn is denied to a non site-admin', () => {
        cy.apollo({
            mutation: gql`mutation($u: String!, $s: String!) { upa { mfaFactors { webauthn {
                resetUserWebauthn(userId: $u, siteKey: $s) } } } }`,
            variables: {u: 'root', s: SITE_KEY},
            errorPolicy: 'all'
        }).then(res => {
            expect(firstErrorMessage(res), 'resetUserWebauthn must be requireSiteAdmin-gated').to.match(DENIED);
        });
    });
});
