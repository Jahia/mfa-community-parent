/**
 * GraphQL coverage for the global MFA configuration surface (extensions bundle):
 *   - mfaExtensionsConfiguration / mfaExtensionsSaveConfiguration round-trip (all six keys,
 *     persisted to the org.jahia.modules.mfa.extensions PID, components hot-reload)
 *   - registeredFactors reflects the installed factor modules
 *   - validation guards: unknown factor, out-of-range graceDays, invalid whitelist entry
 *   - permission gate: a regular user is denied (server administrators only)
 *
 * The defaults are ALWAYS restored in after() — a leftover enforcement policy or login gate
 * would break every other spec's logins.
 */
import {createUser, deleteUser, jfaker} from '@jahia/cypress';
import gql from 'graphql-tag';
import {firstErrorMessage} from './utils';

const ROOT = {username: 'root', password: Cypress.env('SUPER_USER_PASSWORD') as string};

const getConfiguration = () => cy.apollo({
    query: gql`query {
        mfaExtensionsConfiguration {
            enforcedFactors graceDays loginGateEnabled loginGateIpWhitelist loginUrl logoutUrl registeredFactors
        }
    }`,
    fetchPolicy: 'no-cache',
    errorPolicy: 'all'
});

const saveConfiguration = (vars: Record<string, unknown>) => cy.apollo({
    mutation: gql`
        mutation Save($enforcedFactors: [String], $graceDays: Int, $loginGateEnabled: Boolean,
                      $loginGateIpWhitelist: String, $loginUrl: String, $logoutUrl: String) {
            mfaExtensionsSaveConfiguration(
                enforcedFactors: $enforcedFactors, graceDays: $graceDays,
                loginGateEnabled: $loginGateEnabled, loginGateIpWhitelist: $loginGateIpWhitelist,
                loginUrl: $loginUrl, logoutUrl: $logoutUrl) {
                enforcedFactors graceDays loginGateEnabled loginGateIpWhitelist loginUrl logoutUrl
            }
        }`,
    variables: vars,
    errorPolicy: 'all'
});

describe('Global MFA configuration (GraphQL, server admin)', () => {
    beforeEach(() => {
        cy.apolloClient(ROOT);
    });

    after(() => {
        // ALWAYS restore the defaults.
        cy.apolloClient(ROOT);
        saveConfiguration({
            enforcedFactors: [], graceDays: 0, loginGateEnabled: false,
            loginGateIpWhitelist: '', loginUrl: '', logoutUrl: ''
        });
    });

    it('lists the installed factor modules', () => {
        getConfiguration().then(res => {
            const c = res?.data?.mfaExtensionsConfiguration;
            expect(c.registeredFactors, 'both factor modules are installed on the stack')
                .to.include.members(['totp', 'webauthn']);
        });
    });

    it('round-trips the full configuration', () => {
        saveConfiguration({
            enforcedFactors: ['totp'], graceDays: 7, loginGateEnabled: false,
            loginGateIpWhitelist: '203.0.113.7, 10.0.0.0/8',
            loginUrl: '/sites/a/login.html', logoutUrl: '/sites/a/logout.html'
        }).then(res => {
            const c = res?.data?.mfaExtensionsSaveConfiguration;
            expect(c.enforcedFactors).to.deep.eq(['totp']);
            expect(c.graceDays).to.eq(7);
            expect(c.loginGateEnabled).to.be.false;
            expect(c.loginGateIpWhitelist).to.eq('203.0.113.7, 10.0.0.0/8');
            expect(c.loginUrl).to.eq('/sites/a/login.html');
            expect(c.logoutUrl).to.eq('/sites/a/logout.html');
        });
        getConfiguration().then(res => {
            const c = res?.data?.mfaExtensionsConfiguration;
            expect(c.enforcedFactors).to.deep.eq(['totp']);
            expect(c.graceDays).to.eq(7);
        });
        // Null leaves keys unchanged; empty clears.
        saveConfiguration({enforcedFactors: [], graceDays: 0}).then(res => {
            const c = res?.data?.mfaExtensionsSaveConfiguration;
            expect(c.enforcedFactors).to.deep.eq([]);
            expect(c.loginUrl, 'untouched key keeps its value').to.eq('/sites/a/login.html');
        });
        saveConfiguration({loginUrl: '', logoutUrl: '', loginGateIpWhitelist: ''});
    });

    it('rejects an unknown enforced factor (unsatisfiable-policy guard)', () => {
        saveConfiguration({enforcedFactors: ['totq']}).then(res => {
            expect(firstErrorMessage(res), 'typo must be rejected').to.match(/unknown_factor/);
        });
    });

    it('rejects an out-of-range grace period', () => {
        saveConfiguration({graceDays: 9999}).then(res => {
            expect(firstErrorMessage(res)).to.match(/invalid_grace_days/);
        });
        saveConfiguration({graceDays: -1}).then(res => {
            expect(firstErrorMessage(res)).to.match(/invalid_grace_days/);
        });
    });

    it('rejects an invalid whitelist entry', () => {
        saveConfiguration({loginGateIpWhitelist: '10.0.0.0/8, not-an-ip'}).then(res => {
            expect(firstErrorMessage(res)).to.match(/invalid_whitelist/);
        });
    });

    it('denies the configuration to a regular user', () => {
        const usr = jfaker.internet.username();
        const pwd = jfaker.internet.password();
        createUser(usr, pwd);
        cy.apolloClient({username: usr, password: pwd});
        getConfiguration().then(res => {
            expect(firstErrorMessage(res), 'read must be denied').to.match(/denied|permission/i);
        });
        saveConfiguration({graceDays: 1}).then(res => {
            expect(firstErrorMessage(res), 'write must be denied').to.match(/denied|permission/i);
        });
        cy.apolloClient(ROOT);
        deleteUser(usr);
    });
});
