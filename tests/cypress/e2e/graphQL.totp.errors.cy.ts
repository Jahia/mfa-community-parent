/**
 * Error-path coverage for the TOTP factor surface:
 *
 *   - wrong code at confirmEnroll
 *   - confirmEnroll without a prior enroll() (no transient state in the session)
 *   - enroll() on an already-enrolled user without `force` is refused
 *   - enroll(force=true) without a `currentCode` is refused for a non-admin user
 */
import {jfaker, deleteUser} from '@jahia/cypress';
import {
    confirmEnroll,
    createUserForMFA,
    enroll,
    firstErrorMessage,
    totpCode
} from './utils';

describe('TOTP factor - error scenarios', () => {
    let usr: string;
    let pwd: string;

    beforeEach(() => {
        usr = jfaker.internet.username();
        pwd = jfaker.internet.password();
        createUserForMFA(usr, pwd, jfaker.internet.email());
        cy.apolloClient({username: usr, password: pwd});
    });

    afterEach(() => {
        try { deleteUser(usr); } catch (e) { /* ignore */ }
    });

    it('rejects confirmEnroll with a wrong code', () => {
        enroll().then(response => {
            const enr = response?.data?.upa?.mfaFactors?.totp?.enroll;
            expect(enr.secret).to.be.a('string');
            confirmEnroll('123456').then(c => {
                const msg = firstErrorMessage(c);
                expect(msg).to.match(/invalid_code/);
            });
        });
    });

    it('rejects confirmEnroll when there is no transient enrollment state', () => {
        // No prior enroll() — there is no TotpEnrollmentState in the MFA session, so
        // confirmEnroll must surface an internal_error / not_enrolled style error.
        confirmEnroll('000000').then(c => {
            const msg = firstErrorMessage(c);
            expect(msg, 'confirmEnroll without enroll() must fail').to.match(/internal_error|not_enrolled|invalid_code/);
        });
    });

    it('refuses enroll() on an already-enrolled user without force', () => {
        // First, complete a real enrollment.
        enroll().then(response => {
            const enr = response?.data?.upa?.mfaFactors?.totp?.enroll;
            confirmEnroll(totpCode(enr.secret)).then(c => {
                expect(firstErrorMessage(c)).to.be.undefined;
            });
        });

        // Then attempt a second enrollment with no force flag.
        enroll().then(response => {
            const msg = firstErrorMessage(response);
            expect(msg, 'second enroll without force must surface already_enrolled').to.match(/already_enrolled/);
        });
    });

    it('refuses enroll(force=true) for a non-admin user without a currentCode', () => {
        // First enroll the user normally.
        enroll().then(response => {
            const enr = response?.data?.upa?.mfaFactors?.totp?.enroll;
            confirmEnroll(totpCode(enr.secret)).then(c => {
                expect(firstErrorMessage(c)).to.be.undefined;
            });
        });

        // enroll(force=true) without currentCode → force_not_allowed
        enroll(true).then(response => {
            const msg = firstErrorMessage(response);
            expect(msg, 'force without currentCode must be refused').to.match(/force_not_allowed|invalid_code/);
        });
    });
});
