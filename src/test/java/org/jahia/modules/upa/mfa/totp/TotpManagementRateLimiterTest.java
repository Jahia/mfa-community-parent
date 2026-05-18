package org.jahia.modules.upa.mfa.totp;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Verifies the lockout behaviour of the management-mutation rate limiter.
 */
public class TotpManagementRateLimiterTest {

    private TotpManagementRateLimiter limiter;

    @Before
    public void setUp() {
        limiter = new TotpManagementRateLimiter();
    }

    @Test
    public void initiallyNotLockedOut() {
        assertFalse(limiter.isLockedOut("alice"));
    }

    @Test
    public void locksOutAfterMaxFailures() {
        for (int i = 0; i < TotpManagementRateLimiter.MAX_FAILURES - 1; i++) {
            assertFalse(limiter.recordFailure("alice"));
            assertFalse(limiter.isLockedOut("alice"));
        }
        assertTrue(limiter.recordFailure("alice"));
        assertTrue(limiter.isLockedOut("alice"));
    }

    @Test
    public void successClearsFailureCounter() {
        limiter.recordFailure("alice");
        limiter.recordFailure("alice");
        limiter.recordSuccess("alice");
        assertFalse(limiter.isLockedOut("alice"));
        // need another full series to lock again
        for (int i = 0; i < TotpManagementRateLimiter.MAX_FAILURES - 1; i++) {
            assertFalse(limiter.recordFailure("alice"));
        }
        assertTrue(limiter.recordFailure("alice"));
    }

    @Test
    public void perUserIsolation() {
        for (int i = 0; i < TotpManagementRateLimiter.MAX_FAILURES; i++) {
            limiter.recordFailure("alice");
        }
        assertTrue(limiter.isLockedOut("alice"));
        assertFalse(limiter.isLockedOut("bob"));
    }
}
