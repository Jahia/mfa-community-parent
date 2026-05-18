/**
 * Happy-path TOTP enrollment.
 *
 *   1. Authenticate as the user.
 *   2. Call totp.enroll → receive secret + otpauthUri.
 *   3. Compute the current TOTP code from the secret.
 *   4. Call totp.confirmEnroll(code) → receive backup codes.
 *   5. Assert the secret is NOT re-disclosed: calling enroll() again without `force`
 *      must fail with `factor.totp.already_enrolled`.
 */
import {jfaker, deleteUser} from '@jahia/cypress';
import {confirmEnroll, createUserForMFA, enroll, firstErrorMessage, totpCode} from './utils';

describe('TOTP enrollment - happy path', () => {
    let usr: string;
    let pwd: string;

    beforeEach(() => {
        usr = jfaker.internet.username();
        pwd = jfaker.internet.password();
        createUserForMFA(usr, pwd, jfaker.internet.email());
    });

    afterEach(() => {
        try { deleteUser(usr); } catch (e) { /* ignore */ }
    });

    it('enrolls a fresh user, confirms with a generated code, then refuses re-enroll without force', () => {
        // Use an authenticated apollo client for this user.
        cy.apolloClient({username: usr, password: pwd});

        enroll().then(response => {
            const enr = response?.data?.upa?.mfaFactors?.totp?.enroll;
            expect(enr, 'enroll() should succeed').to.not.be.undefined;
            expect(enr.secret, 'secret should be present').to.be.a('string').and.have.length.greaterThan(10);
            expect(enr.otpauthUri).to.match(/^otpauth:\/\/totp\//);
            expect(enr.accountName).to.eq(usr);

            const code = totpCode(enr.secret);
            confirmEnroll(code).then(confirmResponse => {
                const ce = confirmResponse?.data?.upa?.mfaFactors?.totp?.confirmEnroll;
                expect(ce, 'confirmEnroll should succeed').to.not.be.undefined;
                expect(ce.backupCodes).to.be.an('array').and.have.length.greaterThan(0);
                ce.backupCodes.forEach((bc: string) => {
                    expect(bc).to.be.a('string').and.have.length.greaterThan(4);
                });
            });
        });

        // Once enrolled, calling enroll() without force must fail.
        enroll().then(response => {
            const msg = firstErrorMessage(response);
            expect(msg, 'second enroll without force must fail').to.match(/already_enrolled/);
        });
    });

    it('rejects confirmEnroll with a wrong code (no enrollment is persisted)', () => {
        cy.apolloClient({username: usr, password: pwd});

        enroll().then(response => {
            const enr = response?.data?.upa?.mfaFactors?.totp?.enroll;
            expect(enr.secret).to.be.a('string');

            confirmEnroll('000000').then(confirmResponse => {
                const msg = firstErrorMessage(confirmResponse);
                expect(msg, 'confirmEnroll with bogus code must fail').to.match(/invalid_code/);
            });

            // The user is NOT enrolled, so a second enroll() without force should succeed
            // (an unconfirmed enrollment leaves the user un-enrolled in JCR).
            enroll().then(secondResponse => {
                const enr2 = secondResponse?.data?.upa?.mfaFactors?.totp?.enroll;
                expect(enr2.secret, 'should be able to retry enrollment from scratch').to.be.a('string');
            });
        });
    });
});
