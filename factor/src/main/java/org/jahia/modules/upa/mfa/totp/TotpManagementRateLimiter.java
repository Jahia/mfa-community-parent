package org.jahia.modules.upa.mfa.totp;

import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Local per-user attempt counter used to throttle TOTP code checks issued by the management
 * GraphQL mutations ({@code confirmEnroll}, {@code regenerateBackupCodes}, {@code disable},
 * and the privileged {@code enroll(force=true)}).
 * <p>
 * The {@code verify} mutation is already protected by UPA's {@code MfaServiceImpl} lockout;
 * the management surface is protected here because it accepts a code without going through
 * {@code verifyFactor}.
 * <p>
 * The state is in-memory only (per-node, per-bundle restart) — that is intentional: it bounds
 * online brute force without persisting attempt data alongside the user record. A
 * sufficiently determined attacker can wait for the lockout window to elapse.
 */
@Component(service = TotpManagementRateLimiter.class, immediate = true)
public class TotpManagementRateLimiter {

    private static final Logger logger = LoggerFactory.getLogger(TotpManagementRateLimiter.class);

    /** Maximum failures within {@link #WINDOW_MILLIS} before the user is locked out. */
    public static final int MAX_FAILURES = 5;

    /** Sliding-window length: 10 minutes. */
    public static final long WINDOW_MILLIS = 10L * 60L * 1000L;

    private static final class Entry {
        int failures;
        long firstFailureAtMillis;
    }

    private final ConcurrentMap<String, Entry> attempts = new ConcurrentHashMap<>();

    /**
     * Test whether the user is currently locked out from management TOTP checks.
     */
    public boolean isLockedOut(String userId) {
        if (userId == null) {
            return false;
        }
        Entry e = attempts.get(userId);
        if (e == null) {
            return false;
        }
        synchronized (e) {
            if ((System.currentTimeMillis() - e.firstFailureAtMillis) > WINDOW_MILLIS) {
                attempts.remove(userId, e);
                return false;
            }
            return e.failures >= MAX_FAILURES;
        }
    }

    /**
     * Record a failed code attempt. Returns true if the user is now locked out.
     */
    public boolean recordFailure(String userId) {
        if (userId == null) {
            return false;
        }
        Entry e = attempts.computeIfAbsent(userId, k -> new Entry());
        synchronized (e) {
            long now = System.currentTimeMillis();
            if (e.failures == 0 || (now - e.firstFailureAtMillis) > WINDOW_MILLIS) {
                e.firstFailureAtMillis = now;
                e.failures = 1;
            } else {
                e.failures++;
            }
            if (e.failures >= MAX_FAILURES) {
                logger.warn("TOTP management lockout triggered for user {} ({} failures in window)",
                        userId, e.failures);
                return true;
            }
            return false;
        }
    }

    /**
     * Clear the failure counter on success.
     */
    public void recordSuccess(String userId) {
        if (userId != null) {
            attempts.remove(userId);
        }
    }
}
