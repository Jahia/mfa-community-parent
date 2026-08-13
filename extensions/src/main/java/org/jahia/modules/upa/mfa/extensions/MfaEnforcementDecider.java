package org.jahia.modules.upa.mfa.extensions;

import org.apache.commons.lang3.StringUtils;
import org.jahia.modules.upa.mfa.MfaException;
import org.jahia.modules.upa.mfa.MfaService;
import org.jahia.modules.upa.mfa.MfaSession;
import org.jahia.modules.upa.mfa.PreparationContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * The factor-agnostic pick-one / enforcement / grace ORCHESTRATION shared by every MFA factor
 * provider (TOTP, WebAuthn, ...). Both providers used to carry a near-verbatim copy of this
 * decision table; it now lives here once and is parameterized by a small set of factor-specific
 * callbacks ({@link FactorEnforcementCallbacks}).
 * <p>
 * Enforcement is GLOBAL ({@link MfaGlobalPolicy}); a user satisfies it with AT LEAST ONE of the
 * enforced factors and the others skip. The decision rows (identical across factors) are:
 * <ul>
 *   <li>another enforced factor was GENUINELY verified in-session &rarr; skip;</li>
 *   <li>the user has this factor configured &rarr; challenge
 *       ({@link FactorEnforcementCallbacks#buildChallengePreparation()});</li>
 *   <li>this factor not configured, but a sibling enforced factor is &rarr; skip (they verify
 *       with that one);</li>
 *   <li>NO enforced factor configured &rarr; allow during the global grace window, then block
 *       with the factor's {@code enrollment_required} error carrying the inline-enrollable
 *       factors offered for the site.</li>
 * </ul>
 * The circular skip-drain guard ({@link SkippablePreparation#isSkipDrained}) is preserved exactly:
 * a factor drained as skipped carries a verified flag but was never challenged, so it must NOT
 * satisfy pick-one for its siblings.
 * <p>
 * Per-site activation ({@link FactorEnforcementCallbacks#siteApplicability}) is an OPT-IN switch
 * layered ON TOP of the rows above: it may bring a non-enforced factor into play for a site, but it
 * may never suppress a globally enforced factor, nor a factor the user actually OWNS &mdash; see
 * {@link #prepare} for the two halves of the bypass that ordering flaw produced.
 */
public class MfaEnforcementDecider {

    private static final Logger logger = LoggerFactory.getLogger(MfaEnforcementDecider.class);

    private final MfaGlobalPolicy globalPolicy;
    private final MfaService mfaService;
    private final List<MfaSiteProvider> siteProviders;

    public MfaEnforcementDecider(MfaGlobalPolicy globalPolicy, MfaService mfaService,
                                 List<MfaSiteProvider> siteProviders) {
        this.globalPolicy = globalPolicy;
        this.mfaService = mfaService;
        this.siteProviders = siteProviders;
    }

    /**
     * Factor-specific behavior the shared orchestration delegates to. Keeps the JCR / ceremony
     * details in each factor's own bundle.
     */
    public interface FactorEnforcementCallbacks {

        /** The factor type this provider speaks for (e.g. {@code "totp"}, {@code "webauthn"}). */
        String factorType();

        /** Whether the user has this factor configured (TOTP enrolled / a WebAuthn credential). */
        boolean isConfiguredForUser(String userId) throws MfaException;

        /** Return the epoch-millis the enrollment grace window started (initializing on first call). */
        long getOrStartGraceMillis(String userId, long nowMillis) throws MfaException;

        /**
         * The "the user owns this factor, challenge them" preparation. For TOTP this is a no-op
         * marker; for WebAuthn it starts an assertion ceremony.
         */
        Serializable buildChallengePreparation(String userId) throws MfaException;

        /** A "skip this factor for this session" preparation marker. */
        Serializable buildSkippedPreparation();

        /** Record an audit event when enrollment/registration is denied (grace expired / no grace). */
        void recordEnrollmentDenied(String userId, String siteKey, String detail);

        /** The {@code enrollment_required} / {@code registration_required} error code for this factor. */
        String enrollmentRequiredErrorCode();

        /** The {@code internal_error} error code for this factor (thrown when a sibling read fails closed). */
        String internalErrorCode();

        /**
         * The two per-site switches for this user, read from a SINGLE per-site settings load: the
         * factor's {@code enabled} flag on the site, and whether the user is in scope of the site's
         * policy groups ({@code enabledGroups}; empty = everyone). Loading the snapshot once is a
         * correctness invariant &mdash; the enabled check and the group/scope check must see the
         * same site-settings snapshot &mdash; which is why this returns BOTH bits instead of being
         * split into two callbacks.
         * <p>
         * Neither bit can opt a globally enforced factor OUT (see {@link MfaEnforcementDecider#prepare}
         * and {@link SiteApplicability}); they are reported separately only so the decider can say
         * WHICH of the two it overrode.
         */
        SiteApplicability siteApplicability(String userId, String siteKey) throws MfaException;

        /**
         * Throw the factor's no-site, not-enforced, not-configured terminal error
         * ({@code not_enrolled} / {@code not_registered}). Only reached when there is no site
         * context and the factor is not globally enforced.
         */
        MfaException notConfiguredError(String userId);
    }

    /**
     * The two per-site switches a factor exposes for one user, captured from ONE settings snapshot:
     * the site's {@code <factor>.enabled} flag and the user's membership of the site's
     * {@code <factor>.enabledGroups} scope (empty groups = everyone in scope).
     * <p>
     * They are carried separately &mdash; rather than collapsed into a single boolean &mdash; so the
     * decider can report WHICH switch a globally enforced factor overrode. Both are read from the
     * same snapshot, so the enabled flag and the group scope can never come from two different
     * versions of the site's configuration.
     * <p>
     * <b>Neither switch may release a globally enforced factor</b>, group scope included. That looks
     * asymmetric &mdash; the membership test is keyed on the server-known user id &mdash; but the
     * GROUP LIST it is tested against comes from the site's settings, and the site key arrives on
     * {@code mfaInitiate} as a CLIENT-SUPPLIED argument. Honouring it would therefore reopen the
     * bypass {@link MfaEnforcementDecider#prepare} closes, one door further along: a caller holding
     * only a stolen password could name any site whose {@code enabledGroups} excludes the victim and
     * be released from the platform-wide requirement. Scoping enrollment to a subset of users is a
     * platform-wide decision and belongs in {@code enforcedFactors}, not in per-site data.
     */
    public static final class SiteApplicability {

        private final boolean enabledForSite;
        private final boolean userInScope;

        public SiteApplicability(boolean enabledForSite, boolean userInScope) {
            this.enabledForSite = enabledForSite;
            this.userInScope = userInScope;
        }

        /** The site's {@code <factor>.enabled} flag. */
        public boolean isEnabledForSite() {
            return enabledForSite;
        }

        /** Whether the user is inside the site's {@code <factor>.enabledGroups} scope. */
        public boolean isUserInScope() {
            return userInScope;
        }

        /** Whether the factor applies here at all: enabled on the site AND the user in scope. */
        public boolean isApplicable() {
            return enabledForSite && userInScope;
        }
    }

    /**
     * The full {@code prepare} decision, including the per-site activation/scoping shell that both
     * factor providers used to mirror. The per-site switches ({@link SiteApplicability}: the site's
     * {@code enabled} flag and the user's membership of its {@code enabledGroups}) may only ever
     * RELEASE a user who has NOTHING to be challenged with. Two conditions must hold together for
     * the shell to skip the factor:
     * <ul>
     *   <li>the factor is NOT globally enforced &mdash; enforcement is platform-wide and always
     *       runs the pick-one rows below, whatever the site says; and</li>
     *   <li>the user does NOT have this factor configured &mdash; an enrolled user is challenged
     *       even on a site that does not use the factor.</li>
     * </ul>
     * Without a resolvable site, global enforcement still applies (vanity login URLs carry no
     * {@code /sites/<key>} prefix) and the legacy "challenge the configured user, reject the rest"
     * behavior stands when not enforced.
     * <p>
     * <b>Why both conditions are needed (a per-site switch must never SUPPRESS a challenge):</b>
     * the site key travels in the MFA session context, and on the {@code mfaInitiate} entry point it
     * comes straight from a CLIENT-SUPPLIED GraphQL argument, while a "skipped" preparation is
     * accepted by {@code verify} for ANY submission &mdash; an empty code included. Consulting the
     * per-site switch first therefore let a caller who had only proven the password name a site
     * where the factor is not enabled (e.g. {@code systemsite}) and complete authentication with no
     * second factor at all. Checking enforcement alone closed that for platforms that set
     * {@code enforcedFactors}; it left it wide open on the documented per-site opt-in deployment
     * ({@code enforcedFactors} empty, the factor enabled site by site), where an ENROLLED user could
     * still be released by naming another site. Hence the rule this method encodes: <b>a per-site
     * switch may skip an UNCONFIGURED user, never an enrolled one.</b> The resulting Jahia session is
     * global, not site-scoped, so the site named at sign-in can never be a reason to drop a factor
     * the user actually owns.
     * <p>
     * The legitimate opt-in survives untouched: a user who does not own the factor, on a site that
     * has it disabled or that scopes it to groups they are not in, still skips it.
     */
    public Serializable prepare(PreparationContext preparationContext, FactorEnforcementCallbacks callbacks)
            throws MfaException {
        final String factorType = callbacks.factorType();
        String userId = preparationContext.getSessionContext().getUserId();
        String siteKey = preparationContext.getSessionContext().getSiteKey();
        boolean enforced = globalPolicy.isEnforced(factorType);

        if (StringUtils.isNotBlank(siteKey)) {
            // Single site-settings snapshot: the enabled check and the group/scope check must read
            // the SAME snapshot. It is loaded for an enforced factor too - not to decide anything
            // (the enforced rows below apply regardless of the site) but so an overridden per-site
            // scope is REPORTED rather than silently discarded.
            SiteApplicability applicability = callbacks.siteApplicability(userId, siteKey);
            if (enforced) {
                warnIfSiteScopeOverridden(applicability, factorType, userId, siteKey);
            } else if (!applicability.isApplicable() && !callbacks.isConfiguredForUser(userId)) {
                logger.debug("{} skipped for user {} (site '{}' not applicable: disabled or not in scope, "
                        + "the factor is not globally enforced, and the user does not own it)",
                        factorType, userId, siteKey);
                return callbacks.buildSkippedPreparation();
            }
            return prepareForSite(preparationContext, userId, siteKey, callbacks);
        }

        if (enforced) {
            return prepareForGlobalOnly(preparationContext, userId, callbacks);
        }
        if (!callbacks.isConfiguredForUser(userId)) {
            throw callbacks.notConfiguredError(userId);
        }
        return callbacks.buildChallengePreparation(userId);
    }

    /**
     * The enforced decision rows when no site context is available (pick-one semantics minus the
     * per-site activation/scoping rows). Called by the provider after it has determined that the
     * factor is globally enforced and there is no resolvable site.
     */
    private Serializable prepareForGlobalOnly(PreparationContext preparationContext, String userId,
                                              FactorEnforcementCallbacks callbacks) throws MfaException {
        final String factorType = callbacks.factorType();
        if (anotherEnforcedFactorVerified(preparationContext, factorType)) {
            logger.debug("{} skipped for user {} (another enforced factor already verified)",
                    factorType, userId);
            return callbacks.buildSkippedPreparation();
        }
        if (callbacks.isConfiguredForUser(userId)) {
            return callbacks.buildChallengePreparation(userId);
        }
        String sibling = configuredSiblingFactor(userId, callbacks);
        if (sibling != null) {
            warnIfSiblingNotRequired(preparationContext, userId, sibling, factorType);
            logger.debug("{} skipped for user {} (enforced factor {} is configured)",
                    factorType, userId, sibling);
            return callbacks.buildSkippedPreparation();
        }
        return prepareNoEnforcedFactor(userId, null, callbacks);
    }

    /**
     * The site-scoped decision once the site has the factor enabled and the user is in scope.
     * Enforcement is GLOBAL; a user must satisfy it with AT LEAST ONE of the enforced factors.
     */
    private Serializable prepareForSite(PreparationContext preparationContext, String userId, String siteKey,
                                        FactorEnforcementCallbacks callbacks) throws MfaException {
        final String factorType = callbacks.factorType();
        boolean configured = callbacks.isConfiguredForUser(userId);
        if (!globalPolicy.isEnforced(factorType)) {
            if (!configured) {
                logger.debug("{} skipped for user {} (not configured, factor not globally enforced)",
                        factorType, userId);
                return callbacks.buildSkippedPreparation();
            }
            return callbacks.buildChallengePreparation(userId);
        }
        if (anotherEnforcedFactorVerified(preparationContext, factorType)) {
            logger.debug("{} skipped for user {} (another enforced factor already verified)",
                    factorType, userId);
            return callbacks.buildSkippedPreparation();
        }
        if (configured) {
            return callbacks.buildChallengePreparation(userId);
        }
        String sibling = configuredSiblingFactor(userId, callbacks);
        if (sibling != null) {
            warnIfSiblingNotRequired(preparationContext, userId, sibling, factorType);
            logger.debug("{} skipped for user {} (enforced factor {} is configured)",
                    factorType, userId, sibling);
            return callbacks.buildSkippedPreparation();
        }
        return prepareNoEnforcedFactor(userId, siteKey, callbacks);
    }

    /**
     * The user has NONE of the globally enforced factors configured: allow sign-in during the
     * global grace window (per-user start tracked by the factor), then block with the factor's
     * {@code enrollment_required} error carrying the factors the user may enroll inline.
     */
    private Serializable prepareNoEnforcedFactor(String userId, String siteKey,
                                                 FactorEnforcementCallbacks callbacks) throws MfaException {
        long graceDays = globalPolicy.getGraceDays();
        if (graceDays > 0) {
            long now = System.currentTimeMillis();
            long graceStart = callbacks.getOrStartGraceMillis(userId, now);
            if ((now - graceStart) < TimeUnit.DAYS.toMillis(graceDays)) {
                logger.debug("Enrollment grace still active for user {} (started {}, {} days)",
                        userId, graceStart, graceDays);
                return callbacks.buildSkippedPreparation();
            }
        }
        callbacks.recordEnrollmentDenied(userId, siteKey, graceDays > 0 ? "graceExpired" : "noGrace");
        throw new MfaException(callbacks.enrollmentRequiredErrorCode(), "user", userId,
                "enrollableFactors", enrollableFactorsForSite(siteKey));
    }

    /**
     * Whether another globally enforced factor was GENUINELY verified in the current MFA session.
     * A factor drained as skipped also carries the verified flag (the client acknowledges the skip
     * with an empty verify call), but it was never actually challenged &mdash; counting it would
     * let two unchallenged factors skip-drain each other circularly (each pointing at the other)
     * and complete the session with no challenge at all.
     */
    private boolean anotherEnforcedFactorVerified(PreparationContext preparationContext, String factorType) {
        HttpServletRequest request = preparationContext.getHttpServletRequest();
        if (request == null) {
            return false;
        }
        MfaSession session = mfaService.getMfaSession(request);
        if (session == null) {
            return false;
        }
        for (String factor : globalPolicy.getEnforcedFactors()) {
            if (!factorType.equals(factor) && session.isFactorVerified(factor)
                    && !SkippablePreparation.isSkipDrained(session, factor)) {
                return true;
            }
        }
        return false;
    }

    /**
     * The first other globally enforced factor the user has configured (via the sibling
     * {@link MfaSiteProvider}s), or {@code null}. A provider that cannot answer fails CLOSED for
     * sign-in: the error propagates and blocks the login rather than silently skipping a factor.
     */
    private String configuredSiblingFactor(String userId, FactorEnforcementCallbacks callbacks) throws MfaException {
        String factorType = callbacks.factorType();
        for (MfaSiteProvider provider : siteProviders) {
            String type = provider.getFactorType();
            if (factorType.equals(type) || !globalPolicy.isEnforced(type)) {
                continue;
            }
            try {
                if (provider.isConfiguredForUser(userId)) {
                    return type;
                }
            } catch (RuntimeException e) {
                logger.warn("Failed to read {} configuration state for user {}: {}", type, userId, e.getMessage());
                throw new MfaException(callbacks.internalErrorCode());
            }
        }
        return null;
    }

    /**
     * Report a per-site scope that global enforcement just overrode. Only the GROUP scope is warned
     * about here: a site that merely has the factor disabled is already reported, once, on the path
     * that actually denies something ({@link #logEnrollmentOfferedOnDisabledSite}), and repeating it
     * for every sign-in would drown the log.
     * <p>
     * The group case has no other reporting point &mdash; the user is simply enrolled/challenged as
     * if {@code enabledGroups} were empty &mdash; so an operator who configured "enforce TOTP
     * platform-wide, scoped to group staff per site" would otherwise see every user of every site
     * pushed into enrollment with nothing in the log to explain it. See {@link SiteApplicability}
     * for why the scope cannot simply be honoured.
     */
    private void warnIfSiteScopeOverridden(SiteApplicability applicability, String factorType,
                                           String userId, String siteKey) {
        if (!applicability.isEnabledForSite() || applicability.isUserInScope()) {
            return;
        }
        logger.warn("User {} is OUTSIDE the '{}' policy groups configured on site '{}' "
                + "({}.enabledGroups), but '{}' is listed in the global enforcedFactors: the "
                + "platform-wide requirement WINS and the per-site group scope is IGNORED for this "
                + "sign-in (the site key is client-supplied, so it may never release an enforced "
                + "factor). Remove '{}' from enforcedFactors if only some users must own it.",
                userId, factorType, siteKey, factorType, factorType, factorType);
    }

    /**
     * Pick-one hands verification over to the configured sibling factor &mdash; but UPA only ever
     * challenges the factors listed in its own {@code mfaEnabledFactors}. If the sibling is missing
     * there, this sign-in completes with NO second-factor challenge at all: an enforcement bypass
     * caused purely by configuration. Warn loudly instead of blocking &mdash; blocking would
     * dead-end the user, since pre-auth inline enrollment is closed once any enforced factor is
     * owned.
     */
    private void warnIfSiblingNotRequired(PreparationContext preparationContext, String userId,
                                          String sibling, String factorType) {
        List<String> required = preparationContext.getSessionContext().getRequiredFactors();
        if (required == null || !required.contains(sibling)) {
            logger.warn("{} skipped for user {} because enforced factor '{}' is configured, but '{}' is not in "
                    + "UPA's mfaEnabledFactors - this sign-in completes WITHOUT a second-factor challenge. "
                    + "Add it to mfaEnabledFactors (PID org.jahia.modules.upa, typed .config file) so it is "
                    + "actually verified.", factorType, userId, sibling, sibling);
        }
    }

    /**
     * The factors offered for inline enrollment: every globally enforced factor that CAN be set up
     * from the sign-in flow. Factors that cannot (e.g. the email-code adapter) are never offered.
     * <p>
     * Deliberately NOT filtered by per-site enablement, and the {@code siteKey} is carried only for
     * the diagnostic log below. This mirrors {@link #prepare}: once a factor is globally enforced,
     * a per-site switch may no longer opt a user out of it. Filtering here would contradict that -
     * a user on a site where the enforced factor happens to be disabled would be told
     * {@code enrollment_required} and then offered NOTHING to enrol, which is an unrecoverable
     * sign-in. Enforcement is the platform-wide decision; per-site activation only ADDS optional
     * factors, so an enforced factor must remain enrollable everywhere it is enforced.
     */
    private String enrollableFactorsForSite(String siteKey) {
        List<String> offered = new ArrayList<>();
        for (String factor : globalPolicy.getEnforcedFactors()) {
            for (MfaSiteProvider provider : siteProviders) {
                if (!factor.equals(provider.getFactorType()) || !provider.isInlineEnrollable()) {
                    continue;
                }
                offered.add(factor);
                if (StringUtils.isNotBlank(siteKey)) {
                    logEnrollmentOfferedOnDisabledSite(provider, factor, siteKey);
                }
            }
        }
        return String.join(",", offered);
    }

    /**
     * Flag the misconfiguration that used to hide behind the per-site filter: a factor enforced
     * platform-wide but switched off on the site the user is signing in to. Enrollment is offered
     * anyway (see {@link #enrollableFactorsForSite}), so this is a warning, not a decision.
     */
    private void logEnrollmentOfferedOnDisabledSite(MfaSiteProvider provider, String factor, String siteKey) {
        try {
            if (!provider.isEnabledForSite(siteKey)) {
                logger.warn("Offering inline enrollment for '{}' on site '{}' although the factor is DISABLED "
                        + "there: it is listed in the global enforcedFactors, which overrides per-site "
                        + "activation. Enable it on the site, or drop it from enforcedFactors.", factor, siteKey);
            }
        } catch (RuntimeException e) {
            logger.warn("Could not evaluate {} availability on site {}: {}", factor, siteKey, e.getMessage());
        }
    }
}
