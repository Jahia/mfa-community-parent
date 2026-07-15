package org.jahia.modules.upa.mfa.extensions.gql;

import graphql.schema.DataFetchingEnvironment;
import org.junit.Test;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Parameter;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * F11 — anti-IDOR contract for the {@code mfaSessionFactors} query resolver
 * ({@link MfaSessionQueryExtension}) and the scoping guarantees of its result wrapper
 * ({@link MfaSessionFactorsResult}).
 * <p>
 * The security invariant is that the disclosure of "which factors are configured" is scoped to the
 * account whose password the caller already proved: the subject is derived exclusively from the
 * server-side {@code MfaSession}, and the resolver takes <b>no user argument</b>, so a caller can
 * never enumerate another user's factors (IDOR). The full session/OSGi wiring is exercised
 * end-to-end by the login-UI Cypress flow; this test locks the two properties that a refactor could
 * silently regress without the E2E noticing: (1) the resolver never grows a user-id parameter, and
 * (2) the result wrapper is a defensive, session-scoped, immutable view.
 */
public class MfaSessionFactorsResolverTest {

    /**
     * Anti-IDOR structural guard: the resolver must take ONLY the {@link DataFetchingEnvironment}
     * (from which the server derives the session subject) and never a {@code String}/user-id
     * argument that would let a caller target another account. Adding such a parameter is exactly
     * the IDOR regression this guard blocks.
     */
    @Test
    public void resolver_takesNoUserArgument_onlyTheDataFetchingEnvironment() {
        Method resolver = findResolver();
        assertTrue("resolver must be static (a query fetcher, not an instance method)",
                Modifier.isStatic(resolver.getModifiers()));

        Parameter[] params = resolver.getParameters();
        assertEquals("the resolver must take exactly one parameter (the DataFetchingEnvironment)",
                1, params.length);
        assertSame("the sole parameter must be the DataFetchingEnvironment — the subject is derived "
                        + "from the server-side session, never from a caller-supplied argument",
                DataFetchingEnvironment.class, params[0].getType());

        for (Parameter p : params) {
            if (String.class.equals(p.getType()) || CharSequence.class.isAssignableFrom(p.getType())) {
                fail("resolver must not accept a String/user-id argument (IDOR vector): " + p);
            }
        }
    }

    /** The query type must not be freely instantiable (utility holder with a private constructor). */
    @Test
    public void queryExtension_isNotArbitrarilyInstantiable() {
        assertTrue("all constructors of the query extension must be private",
                Arrays.stream(MfaSessionQueryExtension.class.getDeclaredConstructors())
                        .allMatch(c -> Modifier.isPrivate(c.getModifiers())));
    }

    /** A null factor list becomes an empty (never null) list — a guest/absent-directory session. */
    @Test
    public void result_nullFactors_yieldsEmptyList() {
        MfaSessionFactorsResult result = new MfaSessionFactorsResult(null);
        assertNotNull(result.getConfiguredFactors());
        assertTrue("null in → empty (never null) out", result.getConfiguredFactors().isEmpty());
    }

    /** The result carries exactly the session user's own configured factors, verbatim. */
    @Test
    public void result_carriesTheSessionUsersFactorsVerbatim() {
        List<String> factors = Arrays.asList("totp", "webauthn");
        MfaSessionFactorsResult result = new MfaSessionFactorsResult(factors);
        assertEquals(factors, result.getConfiguredFactors());
    }

    /** The returned list is an unmodifiable defensive copy (no caller can mutate session state). */
    @Test
    public void result_listIsUnmodifiable() {
        MfaSessionFactorsResult result = new MfaSessionFactorsResult(Arrays.asList("totp"));
        try {
            result.getConfiguredFactors().add("webauthn");
            fail("the configured-factors list must be unmodifiable");
        } catch (UnsupportedOperationException expected) {
            // expected
        }
        assertFalse(result.getConfiguredFactors().contains("webauthn"));
    }

    private static Method findResolver() {
        for (Method m : MfaSessionQueryExtension.class.getDeclaredMethods()) {
            if ("mfaSessionFactors".equals(m.getName())) {
                return m;
            }
        }
        throw new AssertionError("mfaSessionFactors resolver method not found");
    }
}
