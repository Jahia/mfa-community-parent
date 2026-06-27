package org.jahia.modules.upa.mfa.extensions;

import org.jahia.services.content.JCRTemplate;
import org.jahia.services.content.decorator.JCRUserNode;
import org.jahia.services.usermanager.JahiaUserManagerService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.RepositoryException;

/**
 * Per-user attempt counter that throttles the code/ceremony checks issued by a factor's
 * management GraphQL mutations. The sliding-window arithmetic and the JCR read-modify-write
 * plumbing are shared here; subclasses supply only the factor's JCR namespace
 * (mixin + property names) and keep their distinct {@code upaTotp:} / {@code upaWebauthn:} prefix.
 * <p>
 * State is persisted in shared JCR (a per-factor {@code lockout} mixin on the user node) rather
 * than an in-heap map, so the lockout is <b>cluster-safe</b> and <b>survives a restart</b>. On a
 * JCR error the limiter fails open (does not block) - the underlying check still has to pass, so
 * this only removes the extra throttle, never weakens the actual verification.
 */
public abstract class MfaManagementRateLimiterBase {

    private static final Logger logger = LoggerFactory.getLogger(MfaManagementRateLimiterBase.class);

    /** Maximum failures within {@link #WINDOW_MILLIS} before the user is locked out. */
    public static final int MAX_FAILURES = 5;

    /** Sliding-window length: 10 minutes. */
    public static final long WINDOW_MILLIS = 10L * 60L * 1000L;

    private JahiaUserManagerService userManagerService;

    protected void setUserManagerServiceInternal(JahiaUserManagerService userManagerService) {
        this.userManagerService = userManagerService;
    }

    /** The {@code lockout} mixin node type for this factor (e.g. {@code upaTotp:lockout}). */
    protected abstract String mixinLockout();

    /** The failed-attempts property name for this factor (e.g. {@code upaTotp:failedAttempts}). */
    protected abstract String propFailedAttempts();

    /** The window-start property name for this factor (e.g. {@code upaTotp:windowStart}). */
    protected abstract String propWindowStart();

    /** Human-readable factor name for log messages (e.g. {@code "TOTP"}). */
    protected abstract String factorLabel();

    // --- Pure window arithmetic (unit-tested; the JCR plumbing below is covered by E2E) ---

    /** Whether the given counters represent a locked-out state at {@code now}. */
    public static boolean lockedNow(long failures, long windowStart, long now) {
        if ((now - windowStart) > WINDOW_MILLIS) {
            return false; // window elapsed
        }
        return failures >= MAX_FAILURES;
    }

    /**
     * Compute the next {failures, windowStart} after recording a failure at {@code now}.
     * Opens a fresh window when there was no prior failure or the previous window elapsed.
     */
    public static long[] afterFailure(long failures, long windowStart, long now) {
        if (failures == 0 || (now - windowStart) > WINDOW_MILLIS) {
            return new long[]{1L, now};
        }
        return new long[]{failures + 1, windowStart};
    }

    /** Test whether the user is currently locked out from the management surface. */
    public boolean isLockedOut(String userId) {
        if (userId == null) {
            return false;
        }
        try {
            return Boolean.TRUE.equals(JCRTemplate.getInstance().doExecuteWithSystemSession(session -> {
                JCRUserNode user = userManagerService.lookupUser(userId, session);
                if (user == null || !user.isNodeType(mixinLockout())) {
                    return false;
                }
                long failures = user.hasProperty(propFailedAttempts())
                        ? user.getProperty(propFailedAttempts()).getLong() : 0L;
                long windowStart = user.hasProperty(propWindowStart())
                        ? user.getProperty(propWindowStart()).getLong() : 0L;
                return lockedNow(failures, windowStart, System.currentTimeMillis());
            }));
        } catch (RepositoryException e) {
            // Fail open, but LOUDLY: while JCR is unhealthy the brute-force throttle on the
            // management mutations is disabled (the code check itself still has to pass).
            logger.error("{} management lockout check FAILED OPEN for user {} - brute-force throttling "
                    + "is degraded until JCR recovers; check repository health. Cause: {}",
                    factorLabel(), userId, e.getMessage());
            return false; // fail open
        }
    }

    /** Record a failed attempt. Returns true if the user is now locked out. */
    public boolean recordFailure(String userId) {
        if (userId == null) {
            return false;
        }
        try {
            return Boolean.TRUE.equals(JCRTemplate.getInstance().doExecuteWithSystemSession(session -> {
                JCRUserNode user = userManagerService.lookupUser(userId, session);
                if (user == null) {
                    return false;
                }
                if (!user.isNodeType(mixinLockout())) {
                    user.addMixin(mixinLockout());
                }
                long now = System.currentTimeMillis();
                long failures = user.hasProperty(propFailedAttempts())
                        ? user.getProperty(propFailedAttempts()).getLong() : 0L;
                long windowStart = user.hasProperty(propWindowStart())
                        ? user.getProperty(propWindowStart()).getLong() : 0L;
                long[] next = afterFailure(failures, windowStart, now);
                user.setProperty(propFailedAttempts(), next[0]);
                user.setProperty(propWindowStart(), next[1]);
                session.save();
                if (next[0] >= MAX_FAILURES) {
                    logger.warn("{} management lockout triggered for user {} ({} failures in window)",
                            factorLabel(), userId, next[0]);
                    return true;
                }
                return false;
            }));
        } catch (RepositoryException e) {
            // Fail open, but LOUDLY: a failure that cannot be recorded does not count towards
            // the lockout window, weakening the throttle while JCR is unhealthy.
            logger.error("Failed to record {} lockout failure for user {} - brute-force throttling "
                    + "is degraded until JCR recovers; check repository health. Cause: {}",
                    factorLabel(), userId, e.getMessage());
            return false; // fail open
        }
    }

    /** Clear the failure counter on success. */
    public void recordSuccess(String userId) {
        if (userId == null) {
            return;
        }
        try {
            JCRTemplate.getInstance().doExecuteWithSystemSession(session -> {
                JCRUserNode user = userManagerService.lookupUser(userId, session);
                if (user == null || !user.isNodeType(mixinLockout())) {
                    return null;
                }
                user.setProperty(propFailedAttempts(), 0L);
                user.setProperty(propWindowStart(), 0L);
                session.save();
                return null;
            });
        } catch (RepositoryException e) {
            logger.warn("Failed to clear {} lockout state for user {}: {}", factorLabel(), userId, e.getMessage());
        }
    }
}
