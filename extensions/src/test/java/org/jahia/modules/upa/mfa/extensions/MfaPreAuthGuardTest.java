package org.jahia.modules.upa.mfa.extensions;

import org.jahia.modules.graphql.provider.dxm.DataFetchingException;
import org.jahia.modules.upa.mfa.MfaService;
import org.jahia.modules.upa.mfa.MfaSession;
import org.jahia.modules.upa.mfa.MfaSessionContext;
import org.junit.Before;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Proxy;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

/**
 * The pre-authentication inline enrollment/registration guard {@link MfaPreAuthGuard}: the
 * anti-takeover barrier admitting an unauthenticated caller ONLY with an initiated, error-free MFA
 * session, a globally enforced factor, and a user who owns NO enforced factor - failing CLOSED on
 * any doubt (including an ownership check that throws).
 */
public class MfaPreAuthGuardTest {

    private static final String FACTOR = "totp";
    private static final String ERROR_PREFIX = "factor.totp.";
    private static final String USER = "alice";

    private MfaGlobalPolicy policy;
    private MfaFactorDirectory directory;

    @Before
    public void setUp() {
        policy = new MfaGlobalPolicy();
        directory = new MfaFactorDirectory();
        directory.setGlobalPolicy(policy);
    }

    private void enforce(String enforcedFactors) {
        Map<String, Object> props = new HashMap<>();
        props.put("enforcedFactors", enforcedFactors);
        policy.activate(props);
    }

    /** An MFA service whose getMfaSession() always returns the given session. */
    private static MfaService serviceFor(MfaSession session) {
        return (MfaService) Proxy.newProxyInstance(
                MfaPreAuthGuardTest.class.getClassLoader(), new Class<?>[]{MfaService.class},
                (proxy, method, args) -> "getMfaSession".equals(method.getName()) ? session : defaultReturn(method));
    }

    private static Object defaultReturn(java.lang.reflect.Method method) {
        return boolean.class.equals(method.getReturnType()) ? Boolean.FALSE : null;
    }

    private static HttpServletRequest request() {
        return (HttpServletRequest) Proxy.newProxyInstance(
                MfaPreAuthGuardTest.class.getClassLoader(), new Class<?>[]{HttpServletRequest.class},
                (proxy, method, args) -> null);
    }

    private static MfaSession initiatedSession() {
        MfaSession session = new MfaSession(new MfaSessionContext(
                USER, java.util.Locale.ENGLISH, "siteA", false, Collections.singletonList(FACTOR)));
        session.setInitiated(true);
        return session;
    }

    private static MfaSiteProvider provider(String type, boolean configured) {
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
                return configured;
            }
        };
    }

    private static MfaSiteProvider throwingProvider(String type) {
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
                throw new IllegalStateException("repository unavailable");
            }
        };
    }

    private String run(MfaService service) {
        return MfaPreAuthGuard.requireEnrollmentSubject(request(), FACTOR, ERROR_PREFIX,
                service, policy, directory);
    }

    @Test
    public void eligibleCaller_returnsSubject() {
        enforce(FACTOR);
        directory.bindSiteProvider(provider(FACTOR, false)); // user owns nothing
        assertEquals(USER, run(serviceFor(initiatedSession())));
    }

    @Test
    public void noSession_refuses() {
        enforce(FACTOR);
        assertRefused(serviceFor(null), "not_authenticated");
    }

    @Test
    public void uninitiatedSession_refuses() {
        enforce(FACTOR);
        MfaSession session = new MfaSession(new MfaSessionContext(
                USER, java.util.Locale.ENGLISH, "siteA", false, Collections.singletonList(FACTOR)));
        // setInitiated NOT called -> not initiated
        assertRefused(serviceFor(session), "not_authenticated");
    }

    @Test
    public void erroredSession_refuses() {
        enforce(FACTOR);
        MfaSession session = initiatedSession();
        session.setError(new org.jahia.modules.upa.mfa.MfaError("boom"));
        assertRefused(serviceFor(session), "not_authenticated");
    }

    @Test
    public void enforcementInactiveForFactor_refuses() {
        enforce("webauthn"); // this factor (totp) is not enforced
        directory.bindSiteProvider(provider(FACTOR, false));
        assertRefused(serviceFor(initiatedSession()), "not_authenticated");
    }

    @Test
    public void ownsEnforcedFactor_refuses() {
        enforce(FACTOR);
        directory.bindSiteProvider(provider(FACTOR, true)); // user already owns it
        assertRefused(serviceFor(initiatedSession()), "not_authenticated");
    }

    @Test
    public void ownershipCheckThrows_refusesFailClosed() {
        enforce(FACTOR);
        directory.bindSiteProvider(throwingProvider(FACTOR));
        assertRefused(serviceFor(initiatedSession()), "internal_error");
    }

    private void assertRefused(MfaService service, String expectedSuffix) {
        try {
            run(service);
            fail("expected refusal with " + ERROR_PREFIX + expectedSuffix);
        } catch (DataFetchingException e) {
            assertEquals(ERROR_PREFIX + expectedSuffix, e.getMessage());
        }
    }
}
