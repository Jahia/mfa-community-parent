/**
 * GraphQL coverage for the WebAuthn per-site policy + admin surfaces (the part that does NOT
 * need a browser authenticator):
 *   - setSiteSettings / siteSettings round-trip (enabled, enforced, graceDays, enabledGroups)
 *   - graceDays bound (0..365) guard
 *   - permission gate (non-admin is denied)
 *   - resetUserWebauthn (admin recovery)
 *   - auditEvents (admin actions are recorded)
 *   - enrollmentReport ("who hasn't registered?")
 *   - mfaWebauthn.supported / status for the current user
 *
 * The full registration/assertion ceremony needs a (virtual) authenticator + a secure context;
 * it is exercised manually / by a virtual-authenticator harness, not here.
 */
import {createSite, createUser, deleteSite, deleteUser, jfaker} from '@jahia/cypress';
import gql from 'graphql-tag';
import {firstErrorMessage} from './utils';

const SITE_KEY = 'sample-webauthn-admin';

const ROOT = {username: 'root', password: Cypress.env('SUPER_USER_PASSWORD') as string};

const setSiteSettings = (vars: Record<string, unknown>) => cy.apollo({
    mutation: gql`
        mutation Set($siteKey: String!, $enabled: Boolean!, $enforced: Boolean!, $graceDays: Int, $enabledGroups: [String]) {
            upa { mfaFactors { webauthn { setSiteSettings(siteKey: $siteKey, enabled: $enabled, enforced: $enforced, graceDays: $graceDays, enabledGroups: $enabledGroups) {
                enabled enforced graceDays enabledGroups
            } } } }
        }`,
    variables: vars,
    errorPolicy: 'all'
});

const getSiteSettings = (siteKey: string) => cy.apollo({
    query: gql`query Get($siteKey: String!) { mfaWebauthn { siteSettings(siteKey: $siteKey) { enabled enforced graceDays enabledGroups } } }`,
    variables: {siteKey},
    fetchPolicy: 'no-cache',
    errorPolicy: 'all'
});

const resetUserWebauthn = (userId: string, siteKey: string) => cy.apollo({
    mutation: gql`mutation Reset($userId: String!, $siteKey: String!) { upa { mfaFactors { webauthn { resetUserWebauthn(userId: $userId, siteKey: $siteKey) } } } }`,
    variables: {userId, siteKey},
    errorPolicy: 'all'
});

const auditEvents = (siteKey: string) => cy.apollo({
    query: gql`query Audit($siteKey: String!) { mfaWebauthn { auditEvents(siteKey: $siteKey, limit: 50) { eventType outcome userId } } }`,
    variables: {siteKey},
    fetchPolicy: 'no-cache',
    errorPolicy: 'all'
});

const enrollmentReport = (siteKey: string) => cy.apollo({
    query: gql`query Report($siteKey: String!) { mfaWebauthn { enrollmentReport(siteKey: $siteKey, limit: 200) { totalUsers registeredUsers notRegistered truncated } } }`,
    variables: {siteKey},
    fetchPolicy: 'no-cache',
    errorPolicy: 'all'
});

describe('WebAuthn per-site policy & admin (GraphQL)', () => {
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
        try { deleteSite(SITE_KEY); } catch (e) { /* ignore */ }
    });

    beforeEach(() => {
        cy.apolloClient(ROOT);
    });

    it('reports the factor as supported', () => {
        cy.apollo({
            query: gql`{ mfaWebauthn { supported } }`,
            fetchPolicy: 'no-cache',
            errorPolicy: 'all'
        }).then(res => {
            expect(res?.data?.mfaWebauthn?.supported, 'webauthn factor is implemented').to.be.true;
        });
    });

    it('round-trips per-site policy (enabled, enforced, graceDays, enabledGroups)', () => {
        setSiteSettings({siteKey: SITE_KEY, enabled: true, enforced: true, graceDays: 7, enabledGroups: ['editors', 'reviewers']})
            .then(res => {
                const s = res?.data?.upa?.mfaFactors?.webauthn?.setSiteSettings;
                expect(s.enabled).to.be.true;
                expect(s.enforced).to.be.true;
                expect(s.graceDays).to.eq(7);
                expect(s.enabledGroups).to.have.members(['editors', 'reviewers']);
            });
        getSiteSettings(SITE_KEY).then(res => {
            const s = res?.data?.mfaWebauthn?.siteSettings;
            expect(s.enabled).to.be.true;
            expect(s.enforced).to.be.true;
            expect(s.graceDays).to.eq(7);
            expect(s.enabledGroups).to.have.members(['editors', 'reviewers']);
        });
    });

    it('rejects a grace period above 365 days', () => {
        setSiteSettings({siteKey: SITE_KEY, enabled: true, enforced: true, graceDays: 99999}).then(res => {
            expect(firstErrorMessage(res), 'huge graceDays must be rejected').to.match(/invalid_grace_days/);
        });
        setSiteSettings({siteKey: SITE_KEY, enabled: true, enforced: true, graceDays: 365}).then(res => {
            expect(res?.data?.upa?.mfaFactors?.webauthn?.setSiteSettings?.graceDays, 'max accepted').to.eq(365);
        });
    });

    it('denies setSiteSettings to a non site-admin user', () => {
        const usr = jfaker.internet.username();
        const pwd = jfaker.internet.password();
        createUser(usr, pwd);
        cy.apolloClient({username: usr, password: pwd});
        setSiteSettings({siteKey: SITE_KEY, enabled: true, enforced: false}).then(res => {
            expect(firstErrorMessage(res), 'non-admin must be denied').to.match(/permission_denied|not_authenticated/);
        });
        cy.apolloClient(ROOT);
        deleteUser(usr);
    });

    it('resets a user (admin recovery) and records audit + report', () => {
        const usr = jfaker.internet.username();
        const pwd = jfaker.internet.password();
        createUser(usr, pwd);

        resetUserWebauthn(usr, SITE_KEY).then(res => {
            expect(firstErrorMessage(res)).to.be.undefined;
            expect(res?.data?.upa?.mfaFactors?.webauthn?.resetUserWebauthn).to.be.true;
        });

        auditEvents(SITE_KEY).then(res => {
            const events = res?.data?.mfaWebauthn?.auditEvents;
            expect(events, 'audit events array').to.be.an('array');
            expect(events.map((e: {eventType: string}) => e.eventType)).to.include('reset');
        });

        enrollmentReport(SITE_KEY).then(res => {
            const r = res?.data?.mfaWebauthn?.enrollmentReport;
            expect(r.totalUsers, 'report has a user total').to.be.greaterThan(0);
            expect(r.registeredUsers).to.be.a('number');
            expect(r.notRegistered).to.be.an('array');
        });

        cy.apolloClient(ROOT);
        deleteUser(usr);
    });
});
