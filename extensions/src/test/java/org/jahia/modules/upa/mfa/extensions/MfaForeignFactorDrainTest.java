package org.jahia.modules.upa.mfa.extensions;

import org.jahia.modules.upa.mfa.MfaError;
import org.jahia.modules.upa.mfa.MfaFactorState;
import org.jahia.modules.upa.mfa.MfaService;
import org.jahia.modules.upa.mfa.MfaSession;
import org.jahia.modules.upa.mfa.MfaSessionContext;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

/**
 * Pick-one completion for FOREIGN enforced factors (providers that do not speak the
 * {@link SkippablePreparation} protocol, like UPA's built-in email_code). The drain wraps the
 * standard verify chokepoint; these tests feed it sessions in every relevant state and assert
 * exactly when the foreign factor is released and when the user gets authenticated.
 */
public class MfaForeignFactorDrainTest {

    private static final String USER = "jdoe";
    private static final String TOTP = "totp";
    private static final String WEBAUTHN = "webauthn";
    private static final String EMAIL = "email_code";

    // --- The interesting path: genuine native verification releases the foreign factor -------

    @Test
    public void genuineVerificationDrainsForeignFactorAndAuthenticates() {
        MfaSession session = session(Arrays.asList(TOTP, EMAIL));
        genuinelyVerified(session, TOTP);
        TestDrain drain = drainWith(session, "totp,email_code", TOTP);

        MfaSession out = drain.verifyFactor(TOTP, "123456", null, null);

        assertSame(session, out);
        assertTrue(session.isFactorVerified(EMAIL));
        // The drained factor must carry the skip marker: it was never actually challenged, so it
        // can never satisfy pick-one for anyone else (circular-drain protection).
        assertTrue(SkippablePreparation.isSkipDrained(session, EMAIL));
        assertEquals(1, drain.authenticated);
    }

    @Test
    public void adapterRepresentedFactorIsStillForeign() {
        // Regression: the email_code ADAPTER registers an MfaSiteProvider for directory/chooser
        // purposes — that must not make the factor look native (able to skip itself). A provider
        // flagged isForeignFactor() keeps the factor drainable.
        MfaSession session = session(Arrays.asList(TOTP, EMAIL));
        genuinelyVerified(session, TOTP);
        TestDrain drain = drainWith(session, "totp,email_code", TOTP);
        drain.bindSiteProvider(adapterProvider(EMAIL));

        drain.verifyFactor(TOTP, "123456", null, null);

        assertTrue(session.isFactorVerified(EMAIL));
        assertTrue(SkippablePreparation.isSkipDrained(session, EMAIL));
        assertEquals(1, drain.authenticated);
    }

    @Test
    public void drainOnlyAuthenticatesWhenTheSessionIsActuallyComplete() {
        // webauthn is native: it skips ITSELF on the client walk-through, the drain must leave
        // it alone — and therefore must not authenticate (a factor is still remaining).
        MfaSession session = session(Arrays.asList(TOTP, WEBAUTHN, EMAIL));
        genuinelyVerified(session, TOTP);
        TestDrain drain = drainWith(session, "totp,webauthn,email_code", TOTP, WEBAUTHN);

        drain.verifyFactor(TOTP, "123456", null, null);

        assertTrue(session.isFactorVerified(EMAIL));
        assertFalse(session.isFactorVerified(WEBAUTHN));
        assertEquals(0, drain.authenticated);
    }

    // --- Guards: nothing must ever drain on these paths ---------------------------------------

    @Test
    public void failedVerificationDrainsNothing() {
        MfaSession session = session(Arrays.asList(TOTP, EMAIL));
        // verifyFactor returned without marking totp verified: wrong code.
        TestDrain drain = drainWith(session, "totp,email_code", TOTP);

        drain.verifyFactor(TOTP, "999999", null, null);

        assertFalse(session.isFactorVerified(EMAIL));
        assertEquals(0, drain.authenticated);
    }

    @Test
    public void skipDrainedTriggerNeverReleasesTheForeignFactor() {
        // The verified flag of a drained skip records a client acknowledgment, not a challenge.
        // Counting it would let an unchallenged factor release the only REAL challenge left.
        MfaSession session = session(Arrays.asList(TOTP, EMAIL));
        skipDrained(session, TOTP);
        TestDrain drain = drainWith(session, "totp,email_code", TOTP);

        drain.verifyFactor(TOTP, "", null, null);

        assertFalse(session.isFactorVerified(EMAIL));
        assertEquals(0, drain.authenticated);
    }

    @Test
    public void nonEnforcedVerificationDrainsNothing() {
        // totp verified genuinely but is NOT part of the enforcement policy: pick-one only
        // spans the enforced set, an opt-in factor never excuses an enforced one.
        MfaSession session = session(Arrays.asList(TOTP, EMAIL));
        genuinelyVerified(session, TOTP);
        TestDrain drain = drainWith(session, "email_code", TOTP);

        drain.verifyFactor(TOTP, "123456", null, null);

        assertFalse(session.isFactorVerified(EMAIL));
        assertEquals(0, drain.authenticated);
    }

    @Test
    public void foreignFactorOutsideEnforcementKeepsVanillaAllOfSemantics() {
        // email_code enabled in UPA but NOT enforced here: the operator chose UPA's vanilla
        // "every enabled factor must verify" semantics — the drain must not soften it.
        MfaSession session = session(Arrays.asList(TOTP, EMAIL));
        genuinelyVerified(session, TOTP);
        TestDrain drain = drainWith(session, "totp", TOTP);

        drain.verifyFactor(TOTP, "123456", null, null);

        assertFalse(session.isFactorVerified(EMAIL));
        assertEquals(0, drain.authenticated);
    }

    @Test
    public void erroredSessionIsReturnedUntouched() {
        MfaSession session = session(Arrays.asList(TOTP, EMAIL));
        genuinelyVerified(session, TOTP);
        session.setError(new MfaError("verify.user_suspended", Collections.emptyMap()));
        TestDrain drain = drainWith(session, "totp,email_code", TOTP);

        MfaSession out = drain.verifyFactor(TOTP, "123456", null, null);

        assertSame(session, out);
        assertFalse(session.isFactorVerified(EMAIL));
        assertEquals(0, drain.authenticated);
    }

    @Test
    public void uninitiatedSessionIsReturnedUntouched() {
        MfaSession session = session(Arrays.asList(TOTP, EMAIL));
        session.setInitiated(false);
        genuinelyVerified(session, TOTP);
        TestDrain drain = drainWith(session, "totp,email_code", TOTP);

        drain.verifyFactor(TOTP, "123456", null, null);

        assertFalse(session.isFactorVerified(EMAIL));
        assertEquals(0, drain.authenticated);
    }

    @Test
    public void foreignDrainedPreparationIsASkipMarker() {
        assertTrue(new MfaForeignFactorDrain.ForeignDrainedPreparation().isSkipped());
    }

    // --- Fixtures ------------------------------------------------------------------------------

    /** Records authentications instead of touching Jahia's AuthenticationService. */
    private static class TestDrain extends MfaForeignFactorDrain {
        private int authenticated;

        @Override
        void authenticate(MfaSession session, HttpServletRequest request, HttpServletResponse response) {
            authenticated++;
        }
    }

    private static TestDrain drainWith(MfaSession session, String enforcedFactors, String... nativeFactors) {
        TestDrain drain = new TestDrain();
        MfaGlobalPolicy policy = new MfaGlobalPolicy();
        Map<String, Object> props = new HashMap<>();
        props.put("enforcedFactors", enforcedFactors);
        policy.activate(props);
        drain.setGlobalPolicy(policy);
        drain.setMfaService(verifyingService(session));
        for (String type : nativeFactors) {
            drain.bindSiteProvider(nativeProvider(type));
        }
        return drain;
    }

    /** A fake UPA MfaService whose verifyFactor returns the prebuilt session as-is. */
    private static MfaService verifyingService(MfaSession session) {
        return (MfaService) Proxy.newProxyInstance(MfaService.class.getClassLoader(),
                new Class<?>[]{MfaService.class}, (proxy, method, args) -> {
                    if ("verifyFactor".equals(method.getName())) {
                        return session;
                    }
                    throw new UnsupportedOperationException("unexpected call: " + method.getName());
                });
    }

    private static MfaSiteProvider nativeProvider(String type) {
        return provider(type, false);
    }

    /** A pure adapter speaking ABOUT a foreign factor (mirrors EmailCodeFactorAdapter). */
    private static MfaSiteProvider adapterProvider(String type) {
        return provider(type, true);
    }

    private static MfaSiteProvider provider(String type, boolean foreign) {
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
                return true;
            }

            @Override
            public boolean isForeignFactor() {
                return foreign;
            }
        };
    }

    private static MfaSession session(List<String> requiredFactors) {
        MfaSession session = new MfaSession(
                new MfaSessionContext(USER, Locale.ENGLISH, "digitall", false, requiredFactors));
        session.setInitiated(true);
        return session;
    }

    /** A real challenge: any preparation that is not a skip marker. */
    private static void genuinelyVerified(MfaSession session, String factor) {
        MfaFactorState state = session.getOrCreateFactorState(factor);
        state.setPreparationResult("real-challenge");
        state.setPrepared(true);
        state.setVerified(true);
    }

    /** A drained pick-one skip: verified flag set, but the preparation is a skip marker. */
    private static void skipDrained(MfaSession session, String factor) {
        MfaFactorState state = session.getOrCreateFactorState(factor);
        state.setPreparationResult(new MfaForeignFactorDrain.ForeignDrainedPreparation());
        state.setPrepared(true);
        state.setVerified(true);
    }
}
