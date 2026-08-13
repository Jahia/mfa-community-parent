package org.jahia.modules.upa.mfa.extensions;

import org.jahia.modules.upa.mfa.MfaException;
import org.jahia.modules.upa.mfa.MfaService;
import org.jahia.modules.upa.mfa.MfaSession;
import org.jahia.modules.upa.mfa.MfaSessionContext;
import org.jahia.modules.upa.mfa.PreparationContext;
import org.junit.Before;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * How the shared orchestration combines the GLOBAL enforcement policy ({@link MfaGlobalPolicy}) with
 * the PER-SITE switches
 * ({@link MfaEnforcementDecider.FactorEnforcementCallbacks#siteApplicability}: the site's
 * {@code enabled} flag and the user's membership of its {@code enabledGroups}).
 * <p>
 * Per-site activation is an opt-IN switch: it may bring a non-enforced factor into play for a site,
 * and it may keep such a factor out of the way for a user who does not own it &mdash; but it may
 * never opt OUT a globally enforced factor, nor a factor the user is ENROLLED in. The site key is
 * CLIENT-SUPPLIED on the {@code mfaInitiate} entry point and a "skipped" preparation is accepted by
 * {@code verify} for ANY submission (an empty code included), so every row a per-site switch is
 * allowed to decide is a row where there is nothing to challenge. These tests pin both halves:
 * <ul>
 *   <li>enforced factor + non-applicable site &rarr; the enforced rows still run (the first bypass);</li>
 *   <li>NON-enforced factor + non-applicable site + ENROLLED user &rarr; challenge (the second);</li>
 *   <li>NON-enforced factor + non-applicable site + user who owns nothing &rarr; skip (the
 *       legitimate opt-in, intact).</li>
 * </ul>
 */
public class MfaEnforcementDeciderTest {

    private static final String USER_ID = "alice";
    private static final String FACTOR = "totp";
    /** The site the attacker names: it exists, but has no TOTP configuration at all. */
    private static final String NON_APPLICABLE_SITE = "systemsite";

    private MfaGlobalPolicy policy;
    private MfaSession session;
    private RecordingCallbacks callbacks;
    private final List<MfaSiteProvider> siteProviders = new ArrayList<>();

    @Before
    public void setUp() {
        policy = new MfaGlobalPolicy();
        session = new MfaSession(new MfaSessionContext(
                USER_ID, Locale.ENGLISH, NON_APPLICABLE_SITE, false, Arrays.asList("totp", "webauthn")));
        callbacks = new RecordingCallbacks();
    }

    // --- The bypass: a client-named site must not suppress a globally enforced factor ----------

    @Test
    public void enforcedFactor_isChallengedEvenWhereTheSiteHasItDisabled() throws Exception {
        configurePolicy("totp", 0);
        callbacks.enabledForSite = false; // the named site has no TOTP configuration
        callbacks.configured = true;      // ...but the user IS enrolled

        Serializable prep = decider().prepare(ctx(), callbacks);

        assertFalse("a globally enforced factor the user owns must be challenged whatever the site says",
                isSkipped(prep));
        assertTrue("the challenge preparation is the one built", prep instanceof ChallengePreparation);
    }

    @Test
    public void enforcedFactor_notConfigured_noGrace_blocksInsteadOfSkipping() {
        configurePolicy("totp", 0);
        callbacks.enabledForSite = false;
        callbacks.configured = false; // root NOT enrolled, exactly the reproduced case

        try {
            decider().prepare(ctx(), callbacks);
            fail("expected enrollment_required - a skipped preparation would let an empty code through");
        } catch (MfaException e) {
            assertEquals(RecordingCallbacks.ERROR_ENROLLMENT_REQUIRED, e.getCode());
        }
    }

    @Test
    public void enforcedFactor_notConfigured_onADisabledSite_isStillOfferedForInlineEnrollment() {
        // The other half of the fix above. Blocking an unenrolled user on a site where the enforced
        // factor happens to be DISABLED is only safe if they are still offered a way to enrol: an
        // enrollment_required error carrying an empty enrollableFactors list is an unrecoverable
        // sign-in. Enforcement is platform-wide, so the per-site switch must not filter the offer
        // either - otherwise the security fix trades a bypass for a lockout.
        configurePolicy("totp", 0);
        callbacks.enabledForSite = false;
        callbacks.configured = false;
        siteProviders.add(disabledOnSiteProvider("totp"));

        try {
            decider().prepare(ctx(), callbacks);
            fail("expected enrollment_required");
        } catch (MfaException e) {
            assertEquals(RecordingCallbacks.ERROR_ENROLLMENT_REQUIRED, e.getCode());
            assertEquals("the enforced factor must still be offered for inline enrollment",
                    "totp", e.getArguments().get("enrollableFactors"));
        }
    }

    @Test
    public void enforcedFactor_notConfigured_withinGrace_stillUsesTheGracePath() throws Exception {
        // Grace is the ONLY reason an unenrolled user may pass while enforcement is on; it must
        // still be the grace path that decides it, not the per-site switch.
        configurePolicy("totp", 7);
        callbacks.enabledForSite = false;
        callbacks.configured = false;

        assertTrue(isSkipped(decider().prepare(ctx(), callbacks)));
        assertTrue("the decision must come from the grace window", callbacks.graceConsulted);
    }

    // --- The second half of the bypass: an ENROLLED user is never released by the site ----------

    @Test
    public void notEnforcedFactor_enrolledUser_isChallengedEvenWhereTheSiteHasItDisabled() throws Exception {
        // The same client-supplied site key, one configuration lower: UPA has mfaEnabledFactors=totp
        // but enforcedFactors is EMPTY (the documented per-site opt-in). The user IS enrolled and is
        // normally challenged on their own site; naming a site where TOTP is not enabled must not
        // hand them a skipped preparation, because verify() accepts ANY submission for it - an empty
        // code included. A per-site switch may release a user who owns NOTHING to challenge; it may
        // never release one who owns the factor.
        configurePolicy("", 0);
        callbacks.enabledForSite = false; // the named site has no TOTP configuration
        callbacks.configured = true;      // ...but the user IS enrolled

        Serializable prep = decider().prepare(ctx(), callbacks);

        assertFalse("an enrolled user must be challenged whatever site the request names",
                isSkipped(prep));
        assertTrue("the challenge preparation is the one built", prep instanceof ChallengePreparation);
    }

    // --- Group scoping under enforcement: overridden, but never silently -----------------------

    @Test
    public void enforcedFactor_outOfTheSitesGroupScope_isChallengedAndTheOverrideIsObserved() throws Exception {
        // "Enforce TOTP platform-wide, scoped to group staff per site" is a configuration operators
        // write, and global enforcement overrides it: a user outside the site's enabledGroups is
        // enrolled/challenged anyway, because enabledGroups is per-site data selected by a
        // CLIENT-SUPPLIED site key - honouring it would re-open the bypass through another door.
        // The override must at least be OBSERVED (the decider loads the per-site snapshot and can
        // therefore warn about it) instead of being discarded unseen. It is diagnostics-only, though
        // (see the next test): the enforced rows below never consult the result.
        configurePolicy("totp", 0);
        callbacks.enabledForSite = true;
        callbacks.userInScope = false; // the user is not in the site's policy groups
        callbacks.configured = true;

        Serializable prep = decider().prepare(ctx(), callbacks);

        assertFalse("global enforcement still wins over the per-site group scope", isSkipped(prep));
        assertTrue("the per-site snapshot must be consulted even for an enforced factor, so an "
                + "overridden group scope can be reported instead of silently discarded",
                callbacks.siteConsulted);
    }

    @Test
    public void enforcedFactor_siteApplicabilityThrows_stillChallengesTheConfiguredUser() throws Exception {
        // Regression for the diagnostic-fails-closed bug: for an enforced factor, siteApplicability
        // is consulted ONLY so an overridden group scope can be logged - prepare()'s own decision
        // never depends on it. A provider whose read throws (e.g. a JCR RepositoryException from the
        // group-membership lookup backing it) must therefore never turn into a denied sign-in for a
        // user this factor's actual rows would otherwise challenge without any trouble.
        configurePolicy("totp", 0);
        callbacks.enabledForSite = true;
        callbacks.userInScope = false;
        callbacks.configured = true;
        callbacks.throwOnSiteApplicability = true;

        Serializable prep = decider().prepare(ctx(), callbacks);

        assertFalse("a diagnostic-only read failing must never deny a sign-in the decision does not "
                + "need it for", isSkipped(prep));
        assertTrue("the challenge preparation is still the one built", prep instanceof ChallengePreparation);
    }

    @Test
    public void notEnforcedFactor_outOfTheSitesGroupScope_stillSkipsAnUnconfiguredUser() throws Exception {
        // The group scope keeps its full effect where it is safe: an OPTIONAL factor the user does
        // not own. Nothing can be challenged, so the site's scoping decides.
        configurePolicy("", 0);
        callbacks.enabledForSite = true;
        callbacks.userInScope = false;
        callbacks.configured = false;

        assertTrue(isSkipped(decider().prepare(ctx(), callbacks)));
    }

    // --- The legitimate opt-in behaviour must keep working -------------------------------------

    @Test
    public void notEnforcedFactor_unconfiguredUser_isStillSkippedWhereTheSiteHasItDisabled() throws Exception {
        configurePolicy("", 0);
        callbacks.enabledForSite = false;
        callbacks.configured = false; // nothing to challenge: the site simply does not use TOTP

        assertTrue("per-site disablement still opts a NON-enforced factor out for a user who does "
                        + "not own it", isSkipped(decider().prepare(ctx(), callbacks)));
    }

    @Test
    public void notEnforcedFactor_applicableSite_configuredUser_isChallenged() throws Exception {
        configurePolicy("", 0);
        callbacks.enabledForSite = true;
        callbacks.configured = true;

        assertFalse(isSkipped(decider().prepare(ctx(), callbacks)));
    }

    // --- Pick-one semantics are untouched by the reordering ------------------------------------

    @Test
    public void enforcedFactor_genuinelyVerifiedSibling_stillReleasesThisFactor() throws Exception {
        configurePolicy("totp,webauthn", 0);
        callbacks.enabledForSite = false;
        callbacks.configured = true;
        session.getOrCreateFactorState("webauthn").setVerified(true);

        assertTrue("a genuine sibling verification still satisfies pick-one",
                isSkipped(decider().prepare(ctx(), callbacks)));
    }

    @Test
    public void enforcedFactor_skipDrainedSibling_doesNotReleaseThisFactor() {
        // The circular skip-drain guard: a sibling drained as skipped carries a verified flag but
        // was never challenged, so it must not excuse this factor - even now that the per-site
        // switch no longer hides the decision.
        configurePolicy("totp,webauthn", 0);
        callbacks.enabledForSite = false;
        callbacks.configured = false;
        session.getOrCreateFactorState("webauthn").setPreparationResult(new SkippedPreparation());
        session.getOrCreateFactorState("webauthn").setVerified(true);

        try {
            decider().prepare(ctx(), callbacks);
            fail("expected enrollment_required - a skip-drained sibling is not a real verification");
        } catch (MfaException e) {
            assertEquals(RecordingCallbacks.ERROR_ENROLLMENT_REQUIRED, e.getCode());
        }
    }

    @Test
    public void enforcedFactor_configuredSibling_stillSkips() throws Exception {
        // Pick-one: the user owns the OTHER enforced factor, so this one steps aside (they will
        // verify with the sibling) - the site the request names is irrelevant to that row too.
        configurePolicy("totp,webauthn", 0);
        callbacks.enabledForSite = false;
        callbacks.configured = false;
        siteProviders.add(siblingProvider("webauthn", true));

        assertTrue(isSkipped(decider().prepare(ctx(), callbacks)));
    }

    // --- helpers ---------------------------------------------------------------------------------

    private MfaEnforcementDecider decider() {
        MfaService mfaService = (MfaService) Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class<?>[]{MfaService.class},
                (proxy, method, args) -> "getMfaSession".equals(method.getName()) ? session : null);
        return new MfaEnforcementDecider(policy, mfaService, siteProviders);
    }

    private void configurePolicy(String enforcedFactors, long graceDays) {
        Map<String, Object> props = new HashMap<>();
        props.put("enforcedFactors", enforcedFactors);
        props.put("graceDays", String.valueOf(graceDays));
        policy.activate(props);
    }

    private PreparationContext ctx() {
        HttpServletRequest request = (HttpServletRequest) Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class<?>[]{HttpServletRequest.class},
                (proxy, method, args) -> null);
        return new PreparationContext(session.getContext(), request, null);
    }

    private static boolean isSkipped(Serializable prep) {
        return prep instanceof SkippablePreparation && ((SkippablePreparation) prep).isSkipped();
    }

    /** The factor's "challenge the user" preparation marker. */
    private static class ChallengePreparation implements SkippablePreparation, Serializable {
        @Override
        public boolean isSkipped() {
            return false;
        }
    }

    /** The factor's "this factor is a no-op for this session" preparation marker. */
    private static class SkippedPreparation implements SkippablePreparation, Serializable {
        @Override
        public boolean isSkipped() {
            return true;
        }
    }

    /** A provider for a factor that is installed and inline-enrollable but DISABLED on every site. */
    private static MfaSiteProvider disabledOnSiteProvider(String type) {
        return new MfaSiteProvider() {
            @Override
            public String getFactorType() {
                return type;
            }

            @Override
            public boolean isEnabledForSite(String siteKey) {
                return false;
            }

            @Override
            public boolean isAnySiteEnabled() {
                return false;
            }

            @Override
            public boolean isConfiguredForUser(String userId) {
                return false;
            }
        };
    }

    /** A sibling factor's per-user configuration view (only {@code isConfiguredForUser} matters here). */
    private static MfaSiteProvider siblingProvider(String type, boolean configuredForUser) {
        return new MfaSiteProvider() {
            @Override
            public String getFactorType() {
                return type;
            }

            @Override
            public boolean isEnabledForSite(String siteKey) {
                return true;
            }

            @Override
            public boolean isAnySiteEnabled() {
                return true;
            }

            @Override
            public boolean isConfiguredForUser(String userId) {
                return configuredForUser;
            }
        };
    }

    /** Stands in for a factor bundle's callbacks, with the two switches driven from the tests. */
    private static class RecordingCallbacks implements MfaEnforcementDecider.FactorEnforcementCallbacks {

        static final String ERROR_ENROLLMENT_REQUIRED = "factor.test.enrollment_required";

        /** The site's {@code <factor>.enabled} flag. */
        boolean enabledForSite = true;
        /** Whether the user is inside the site's {@code <factor>.enabledGroups} scope. */
        boolean userInScope = true;
        boolean configured;
        boolean graceConsulted;
        /** Whether the decider loaded the per-site snapshot at all (it must, even when enforced). */
        boolean siteConsulted;
        /** When true, {@link #siteApplicability} throws instead of returning - simulates a JCR failure. */
        boolean throwOnSiteApplicability;

        @Override
        public String factorType() {
            return FACTOR;
        }

        @Override
        public boolean isConfiguredForUser(String userId) {
            return configured;
        }

        @Override
        public long getOrStartGraceMillis(String userId, long nowMillis) {
            graceConsulted = true;
            return nowMillis; // the window starts now
        }

        @Override
        public Serializable buildChallengePreparation(String userId) {
            return new ChallengePreparation();
        }

        @Override
        public Serializable buildSkippedPreparation() {
            return new SkippedPreparation();
        }

        @Override
        public void recordEnrollmentDenied(String userId, String siteKey, String detail) {
            // no-op
        }

        @Override
        public String enrollmentRequiredErrorCode() {
            return ERROR_ENROLLMENT_REQUIRED;
        }

        @Override
        public String internalErrorCode() {
            return "factor.test.internal_error";
        }

        @Override
        public MfaEnforcementDecider.SiteApplicability siteApplicability(String userId, String siteKey)
                throws MfaException {
            siteConsulted = true;
            if (throwOnSiteApplicability) {
                throw new MfaException("factor.test.internal_error", "user", userId);
            }
            return new MfaEnforcementDecider.SiteApplicability(enabledForSite, userInScope);
        }

        @Override
        public MfaException notConfiguredError(String userId) {
            return new MfaException("factor.test.not_enrolled", "user", userId);
        }
    }
}
