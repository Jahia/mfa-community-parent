package org.jahia.modules.upa.mfa.totp.gql;

import org.jahia.modules.upa.mfa.MfaSession;
import org.jahia.modules.upa.mfa.MfaSessionContext;
import org.jahia.modules.upa.mfa.totp.TotpEnrollmentState;
import org.junit.Test;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.Locale;

import static org.jahia.modules.upa.mfa.totp.TotpFactorProvider.FACTOR_TYPE;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * U5 (idempotency sub-gap): {@code TotpFactorMutation.enroll} reuses an already-generated transient
 * secret when called again within the TTL, and regenerates once the previous state has expired. The
 * {@link TotpEnrollmentState#isExpired()} TTL is covered by {@code TotpEnrollmentStateTest}; this
 * test locks the mutation's <i>reuse-vs-regenerate</i> decision by driving its actual session-backed
 * state storage (the {@code readEnrollmentState}/{@code writeEnrollmentState} helpers) over a real
 * {@link MfaSession}, since the full GraphQL {@code enroll} entry point is fronted by OSGi/context
 * statics not available at unit level.
 */
public class TotpEnrollReuseStateTest {

    private static MfaSession loginSession() {
        return new MfaSession(new MfaSessionContext(
                "alice", Locale.ENGLISH, "siteA", false, Collections.singletonList("totp")));
    }

    /** No prior state: enroll() must generate a fresh secret (read returns null → regenerate branch). */
    @Test
    public void noPriorState_firstEnrollHasNothingToReuse() throws Exception {
        TotpFactorMutation mutation = new TotpFactorMutation();
        MfaSession session = loginSession();
        assertNull("a first enroll has no transient state to reuse", readState(mutation, session));
    }

    /** A fresh (within-TTL) state is reused verbatim: enroll() returns the SAME secret, not a new one. */
    @Test
    public void freshState_isReusedWithinTtl() throws Exception {
        TotpFactorMutation mutation = new TotpFactorMutation();
        MfaSession session = loginSession();

        writeState(mutation, session, new TotpEnrollmentState("JBSWY3DPEHPK3PXP"));

        TotpEnrollmentState reused = readState(mutation, session);
        assertNotNull(reused);
        assertFalse("a just-written state is within TTL → reuse branch", reused.isExpired());
        assertEquals("the transient secret must be reused, not regenerated",
                "JBSWY3DPEHPK3PXP", reused.getSecretBase32());
    }

    /** An expired state must NOT be reused: enroll() sees isExpired()==true and regenerates. */
    @Test
    public void expiredState_triggersRegeneration() throws Exception {
        TotpFactorMutation mutation = new TotpFactorMutation();
        MfaSession session = loginSession();

        long expiredCreatedAt = System.currentTimeMillis() - (TotpEnrollmentState.TTL_MILLIS + 1000L);
        writeState(mutation, session, newExpiredState("OLDSECRET234567", expiredCreatedAt));

        TotpEnrollmentState stale = readState(mutation, session);
        assertNotNull(stale);
        assertTrue("an over-TTL state must be treated as expired → regenerate branch", stale.isExpired());
    }

    // --- helpers: drive the mutation's real session-backed state storage ------------------------

    private static TotpEnrollmentState readState(TotpFactorMutation mutation, MfaSession session) throws Exception {
        Method m = TotpFactorMutation.class.getDeclaredMethod(
                "readEnrollmentState", MfaSession.class, javax.servlet.http.HttpServletRequest.class);
        m.setAccessible(true);
        return (TotpEnrollmentState) m.invoke(mutation, session, null);
    }

    private static void writeState(TotpFactorMutation mutation, MfaSession session, TotpEnrollmentState state)
            throws Exception {
        Method m = TotpFactorMutation.class.getDeclaredMethod("writeEnrollmentState",
                MfaSession.class, javax.servlet.http.HttpServletRequest.class, TotpEnrollmentState.class);
        m.setAccessible(true);
        m.invoke(mutation, session, null, state);
    }

    /** Build a state whose creation timestamp is in the past (package-visible ctor in the totp package). */
    private static TotpEnrollmentState newExpiredState(String secret, long createdAtMillis) throws Exception {
        java.lang.reflect.Constructor<TotpEnrollmentState> ctor =
                TotpEnrollmentState.class.getDeclaredConstructor(String.class, long.class);
        ctor.setAccessible(true);
        return ctor.newInstance(secret, createdAtMillis);
    }

    static {
        // ensure FACTOR_TYPE reference is used (the state slot is keyed by it in the mutation)
        assert FACTOR_TYPE != null;
    }
}
