package org.jahia.modules.upa.mfa.webauthn;

import org.jahia.services.content.JCRTemplate;
import org.jahia.services.content.decorator.JCRUserNode;
import org.jahia.services.usermanager.JahiaUserManagerService;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.RepositoryException;

/**
 * Per-user attempt counter that throttles the WebAuthn registration management surface
 * ({@code startRegistration} / {@code finishRegistration} on the pre-authentication inline
 * enrollment path, where the caller has only proved the password).
 * <p>
 * The {@code verify} mutation is already protected by UPA's {@code MfaServiceImpl} lockout.
 * State is persisted in shared JCR (the {@code upaWebauthn:lockout} mixin on the user node) so
 * the lockout is <b>cluster-safe</b> and <b>survives a restart</b> — mirrors
 * {@code TotpManagementRateLimiter}. On a JCR error the limiter fails open (does not block):
 * the attestation validation itself still has to pass, so this only removes the extra
 * throttle, never weakens the ceremony.
 */
@Component(service = WebAuthnManagementRateLimiter.class, immediate = true)
public class WebAuthnManagementRateLimiter {

    private static final Logger logger = LoggerFactory.getLogger(WebAuthnManagementRateLimiter.class);

    /** Maximum failures within {@link #WINDOW_MILLIS} before the user is locked out. */
    public static final int MAX_FAILURES = 5;

    /** Sliding-window length: 10 minutes. */
    public static final long WINDOW_MILLIS = 10L * 60L * 1000L;

    static final String MIXIN_LOCKOUT = "upaWebauthn:lockout";
    static final String PROP_FAILED_ATTEMPTS = "upaWebauthn:failedAttempts";
    static final String PROP_WINDOW_START = "upaWebauthn:windowStart";

    private JahiaUserManagerService userManagerService;

    @Reference
    public void setUserManagerService(JahiaUserManagerService userManagerService) {
        this.userManagerService = userManagerService;
    }

    // --- Pure window arithmetic (unit-tested; the JCR plumbing below is covered by E2E) ---

    /** Whether the given counters represent a locked-out state at {@code now}. */
    static boolean lockedNow(long failures, long windowStart, long now) {
        if ((now - windowStart) > WINDOW_MILLIS) {
            return false; // window elapsed
        }
        return failures >= MAX_FAILURES;
    }

    /**
     * Compute the next {failures, windowStart} after recording a failure at {@code now}.
     * Opens a fresh window when there was no prior failure or the previous window elapsed.
     */
    static long[] afterFailure(long failures, long windowStart, long now) {
        if (failures == 0 || (now - windowStart) > WINDOW_MILLIS) {
            return new long[]{1L, now};
        }
        return new long[]{failures + 1, windowStart};
    }

    /** Test whether the user is currently locked out from registration management. */
    public boolean isLockedOut(String userId) {
        if (userId == null) {
            return false;
        }
        try {
            return Boolean.TRUE.equals(JCRTemplate.getInstance().doExecuteWithSystemSession(session -> {
                JCRUserNode user = userManagerService.lookupUser(userId, session);
                if (user == null || !user.isNodeType(MIXIN_LOCKOUT)) {
                    return false;
                }
                long failures = user.hasProperty(PROP_FAILED_ATTEMPTS)
                        ? user.getProperty(PROP_FAILED_ATTEMPTS).getLong() : 0L;
                long windowStart = user.hasProperty(PROP_WINDOW_START)
                        ? user.getProperty(PROP_WINDOW_START).getLong() : 0L;
                return lockedNow(failures, windowStart, System.currentTimeMillis());
            }));
        } catch (RepositoryException e) {
            logger.error("WebAuthn management lockout check FAILED OPEN for user {} — brute-force throttling "
                    + "is degraded until JCR recovers; check repository health. Cause: {}",
                    userId, e.getMessage());
            return false; // fail open
        }
    }

    /** Record a failed registration attempt. Returns true if the user is now locked out. */
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
                if (!user.isNodeType(MIXIN_LOCKOUT)) {
                    user.addMixin(MIXIN_LOCKOUT);
                }
                long now = System.currentTimeMillis();
                long failures = user.hasProperty(PROP_FAILED_ATTEMPTS)
                        ? user.getProperty(PROP_FAILED_ATTEMPTS).getLong() : 0L;
                long windowStart = user.hasProperty(PROP_WINDOW_START)
                        ? user.getProperty(PROP_WINDOW_START).getLong() : 0L;
                long[] next = afterFailure(failures, windowStart, now);
                user.setProperty(PROP_FAILED_ATTEMPTS, next[0]);
                user.setProperty(PROP_WINDOW_START, next[1]);
                session.save();
                if (next[0] >= MAX_FAILURES) {
                    logger.warn("WebAuthn management lockout triggered for user {} ({} failures in window)",
                            userId, next[0]);
                    return true;
                }
                return false;
            }));
        } catch (RepositoryException e) {
            logger.error("Failed to record WebAuthn lockout failure for user {} — brute-force throttling "
                    + "is degraded until JCR recovers; check repository health. Cause: {}",
                    userId, e.getMessage());
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
                if (user == null || !user.isNodeType(MIXIN_LOCKOUT)) {
                    return null;
                }
                user.setProperty(PROP_FAILED_ATTEMPTS, 0L);
                user.setProperty(PROP_WINDOW_START, 0L);
                session.save();
                return null;
            });
        } catch (RepositoryException e) {
            logger.warn("Failed to clear WebAuthn lockout state for user {}: {}", userId, e.getMessage());
        }
    }
}
