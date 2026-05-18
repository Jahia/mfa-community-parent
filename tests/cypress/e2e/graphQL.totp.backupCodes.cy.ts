/**
 * Backup-code coverage:
 *
 *   1. A backup code returned by confirmEnroll can be used at totp.verify exactly once.
 *      A second use of the same backup code fails.
 *   2. regenerateBackupCodes requires a valid current TOTP code:
 *      - call with bogus code → rejected
 *      - call with a fresh TOTP code → succeeds, returns a fresh list, old codes are
 *        invalidated.
 */
import {jfaker, deleteUser} from '@jahia/cypress';
import {
    confirmEnroll,
    createUserForMFA,
    enroll,
    firstErrorMessage,
    initiate,
    prepareTotp,
    regenerateBackupCodes,
    totpCode,
    nextWindowCode,
    verifyTotp
} from './utils';

describe('TOTP backup codes', () => {
    let usr: string;
    let pwd: string;
    let secret: string;
    let backupCodes: string[];
    // Collect every user we create so the spec can wipe them in a single `after()`.
    // Doing cleanup once per spec (instead of per test) avoids the `cy.readFile` timeout
    // we were hitting on the heavier backup-code spec — see SUPPORT-591.
    const createdUsers: string[] = [];

    beforeEach(() => {
        usr = jfaker.internet.username();
        pwd = jfaker.internet.password();
        createdUsers.push(usr);
        createUserForMFA(usr, pwd, jfaker.internet.email());

        cy.apolloClient({username: usr, password: pwd});
        enroll().then(response => {
            const enr = response?.data?.upa?.mfaFactors?.totp?.enroll;
            secret = enr.secret;
            confirmEnroll(totpCode(secret)).then(c => {
                const ce = c?.data?.upa?.mfaFactors?.totp?.confirmEnroll;
                backupCodes = ce.backupCodes;
                expect(backupCodes).to.be.an('array').and.have.length.greaterThan(0);
            });
        });
    });

    after(() => {
        createdUsers.forEach(name => {
            try { deleteUser(name); } catch (e) { /* ignore */ }
        });
    });

    it('a backup code works at login exactly once, then is invalidated', () => {
        cy.logout();

        // First use of a backup code: should succeed.
        initiate(usr, pwd);
        prepareTotp();
        cy.then(() => {
            const bc = backupCodes[0];
            verifyTotp(bc).then(response => {
                expect(firstErrorMessage(response), 'first use of backup code should succeed').to.be.undefined;
                const verified = response?.data?.upa?.mfaFactors?.totp?.verify?.session?.verifiedFactors;
                expect(verified).to.include('totp');
            });

            // Second use of the same backup code in a fresh MFA session: must fail.
            initiate(usr, pwd);
            prepareTotp();
            verifyTotp(bc).then(response => {
                // Replay rejection surfaces on the factor-level state, not session-level.
                const msg = firstErrorMessage(response);
                const sess = response?.data?.upa?.mfaFactors?.totp?.verify?.session;
                const factorErr = sess?.factorState?.error?.code;
                const verified = sess?.verifiedFactors || [];
                const failed = (msg && /invalid|verification_failed/i.test(msg))
                    || (factorErr && /verification_failed|invalid/i.test(factorErr))
                    || (!verified.includes('totp'));
                expect(failed,
                    `replayed backup code must be rejected (msg=${msg}, factorErr=${factorErr}, verified=${JSON.stringify(verified)})`)
                    .to.be.true;
            });
        });
    });

    it('regenerateBackupCodes requires a valid current TOTP code', () => {
        // Wrong code → rejected.
        regenerateBackupCodes('000000').then(response => {
            const msg = firstErrorMessage(response);
            expect(msg, 'regen with bogus code must fail').to.match(/invalid_code/);
        });

        // Valid fresh code → succeeds and returns a new set.
        // PBKDF2 hashing of the fresh backup-code batch (120k iterations × 10 codes) can push
        // the round-trip beyond Cypress's default 4s cy.then() budget on a cold JCR.
        cy.then({timeout: 30000}, () => {
            const freshCode = nextWindowCode(secret);
            regenerateBackupCodes(freshCode).then(response => {
                expect(firstErrorMessage(response)).to.be.undefined;
                const fresh = response?.data?.upa?.mfaFactors?.totp?.regenerateBackupCodes?.backupCodes;
                expect(fresh).to.be.an('array').and.have.length.greaterThan(0);
                // Sanity: regenerated set should differ from the original.
                expect(fresh).to.not.deep.equal(backupCodes);
            });
        });
    });
});
