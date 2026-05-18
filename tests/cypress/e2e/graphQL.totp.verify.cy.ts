/**
 * TOTP login verification.
 *
 *   1. Enroll user (so a secret is persisted on the user node).
 *   2. Open a fresh anonymous session, run mfaInitiate(user, pwd).
 *   3. Call totp.prepare, then totp.verify(<freshly-computed code>) → expect success.
 *   4. Replay the SAME code → must fail (lastUsedCounter prevents reuse).
 */
import {jfaker, deleteUser} from '@jahia/cypress';
import {
    confirmEnroll,
    createUserForMFA,
    enroll,
    firstErrorMessage,
    initiate,
    prepareTotp,
    totpCode,
    verifyTotp,
    nextWindowCode
} from './utils';

describe('TOTP verify (login flow)', () => {
    let usr: string;
    let pwd: string;
    let secret: string;

    beforeEach(() => {
        usr = jfaker.internet.username();
        pwd = jfaker.internet.password();
        createUserForMFA(usr, pwd, jfaker.internet.email());

        cy.apolloClient({username: usr, password: pwd});
        enroll().then(response => {
            const enr = response?.data?.upa?.mfaFactors?.totp?.enroll;
            secret = enr.secret;
            confirmEnroll(totpCode(secret)).then(c => {
                expect(firstErrorMessage(c)).to.be.undefined;
            });
        });
        // Drop the authenticated session so the login flow below starts unauthenticated.
        cy.logout();
    });

    afterEach(() => {
        try { deleteUser(usr); } catch (e) { /* ignore */ }
    });

    it('accepts a fresh TOTP code at login', () => {
        initiate(usr, pwd);
        prepareTotp();

        // Use a code from a future window to ensure it has not yet been consumed by
        // enrollment-time `updateLastUsedCounter`.
        const code = nextWindowCode(secret);
        verifyTotp(code).then(response => {
            expect(firstErrorMessage(response), 'verify with fresh code should succeed').to.be.undefined;
            const verified = response?.data?.upa?.mfaFactors?.totp?.verify?.session?.verifiedFactors;
            expect(verified, 'totp should be in verifiedFactors').to.include('totp');
        });
    });

    it('rejects a replayed TOTP code (same code used twice → second fails)', () => {
        initiate(usr, pwd);
        prepareTotp();

        const code = nextWindowCode(secret);
        verifyTotp(code).then(first => {
            expect(firstErrorMessage(first), 'first use of the code should succeed').to.be.undefined;
        });

        // Re-initiate a new MFA session and try the SAME code again.
        initiate(usr, pwd);
        prepareTotp();
        verifyTotp(code).then(second => {
            // Replay rejection surfaces as a factor-LEVEL error (factorState.error), not a
            // session-level error: MfaServiceImpl sets ERROR_VERIFICATION_FAILED on the
            // factor state and leaves the session itself intact so the user can retry.
            const msg = firstErrorMessage(second);
            const sess = second?.data?.upa?.mfaFactors?.totp?.verify?.session;
            const factorErr = sess?.factorState?.error?.code;
            const verified = sess?.verifiedFactors || [];
            const failed = (msg && /invalid|verification_failed|replay/i.test(msg))
                || (factorErr && /verification_failed|invalid/i.test(factorErr))
                || (!verified.includes('totp'));
            expect(failed,
                `replayed code must be rejected (msg=${msg}, factorErr=${factorErr}, verified=${JSON.stringify(verified)})`)
                .to.be.true;
        });
    });
});
