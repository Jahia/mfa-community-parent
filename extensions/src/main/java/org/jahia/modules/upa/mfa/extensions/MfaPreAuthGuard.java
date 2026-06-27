package org.jahia.modules.upa.mfa.extensions;

import org.jahia.modules.graphql.provider.dxm.DataFetchingException;
import org.jahia.modules.upa.mfa.MfaService;
import org.jahia.modules.upa.mfa.MfaSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;

/**
 * The pre-authentication inline enrollment/registration guard, shared by every factor's mutation.
 * Enrollment without an authenticated user is admitted ONLY when ALL of the following hold
 * (fails CLOSED on any doubt):
 * <ol>
 *   <li>an initiated, error-free MFA session exists (the password was already validated);</li>
 *   <li>this factor is part of the global enforcement policy
 *       ({@link MfaGlobalPolicy#isEnforced(String)});</li>
 *   <li>the session user owns NO globally enforced factor
 *       ({@link MfaFactorDirectory#hasAnyEnforcedFactorConfigured(String)}) - the anti-takeover
 *       barrier: a caller who only proved the password must never add a factor to an account that
 *       already has one (that would replace the legitimate owner's second factor).</li>
 * </ol>
 * The ownership check is the load-bearing barrier and fails closed: if the directory cannot
 * answer (unhealthy repository) the guard refuses the enrollment.
 */
public final class MfaPreAuthGuard {

    private static final Logger logger = LoggerFactory.getLogger(MfaPreAuthGuard.class);

    private MfaPreAuthGuard() {
        // utility
    }

    /**
     * Validate the pre-auth enrollment request and return the enrollment subject (the MFA-session
     * user id), or throw a {@link DataFetchingException} carrying a factor-specific error code.
     *
     * @param request         the current servlet request
     * @param factorType      the factor type (e.g. {@code "totp"})
     * @param errorPrefix     the factor's error-code prefix (e.g. {@code "factor.totp."}); surfaced
     *                        codes are {@code <prefix>not_authenticated} and {@code <prefix>internal_error}
     * @param mfaService      UPA's MFA service (to read the session)
     * @param globalPolicy    the global enforcement policy
     * @param factorDirectory the aggregated factor directory (ownership check)
     * @return the MFA-session user id (the enrollment subject)
     */
    public static String requireEnrollmentSubject(HttpServletRequest request, String factorType,
                                                  String errorPrefix, MfaService mfaService,
                                                  MfaGlobalPolicy globalPolicy,
                                                  MfaFactorDirectory factorDirectory) {
        MfaSession session = mfaService.getMfaSession(request);
        if (session == null || !session.isInitiated() || session.hasError()) {
            throw new DataFetchingException(errorPrefix + "not_authenticated");
        }
        if (!globalPolicy.isEnforced(factorType)) {
            throw new DataFetchingException(errorPrefix + "not_authenticated");
        }
        String userId = session.getContext().getUserId();
        boolean ownsEnforcedFactor;
        try {
            ownsEnforcedFactor = factorDirectory.hasAnyEnforcedFactorConfigured(userId);
        } catch (RuntimeException e) {
            logger.error("Could not evaluate factor ownership for user {} (refusing pre-auth {} enrollment): {}",
                    userId, factorType, e.getMessage());
            throw new DataFetchingException(errorPrefix + "internal_error");
        }
        if (ownsEnforcedFactor) {
            logger.warn("Refused pre-auth {} enrollment for user {}: an enforced factor is already configured",
                    factorType, userId);
            throw new DataFetchingException(errorPrefix + "not_authenticated");
        }
        return userId;
    }
}
