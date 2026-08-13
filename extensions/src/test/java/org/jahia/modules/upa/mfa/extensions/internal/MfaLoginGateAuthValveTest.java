package org.jahia.modules.upa.mfa.extensions.internal;

import org.jahia.params.valves.AuthValveContext;
import org.jahia.pipelines.Pipeline;
import org.jahia.pipelines.PipelineException;
import org.jahia.pipelines.valves.Valve;
import org.jahia.pipelines.valves.ValveContext;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * The auth valve is the decisive block for a password-only {@code /cms/login} POST (the servlet
 * filter runs too late for POST). With a stubbed {@link MfaLoginGateDecision} it must:
 * <ul>
 *   <li>let a non-login request (missing username/password) continue the pipeline;</li>
 *   <li>continue the pipeline for a whitelisted client (the emergency door);</li>
 *   <li>continue the pipeline when not gated;</li>
 *   <li>BLOCK a gated, non-whitelisted password login - NOT continue the pipeline, and write a
 *       redirect to the configured login page (or {@code 403} when none is distinct);</li>
 *   <li>continue the pipeline (defense to the servlet filter) when the decision service is absent;</li>
 *   <li>leave a password carried in the {@code Authorization} header ALONE unless the operator armed
 *       {@code loginGate.gateBasicAuth} - that shape reaches every endpoint, so it is opt-in;</li>
 *   <li>once armed, gate that header the same way, answering {@code 403} (a non-interactive caller
 *       has no login page to follow) and leaving a token scheme alone;</li>
 *   <li>register at the head of the pipeline, ahead of both valves that consume a password.</li>
 *   <li>mark the request as handled ({@link MfaLoginGateAuthValve#ATTR_HANDLED}) whenever it blocks
 *       - and only then - so {@link MfaLoginGateFilter} does not try to write a second terminal
 *       response over an already-committed one (see the class javadoc on that coupling).</li>
 * </ul>
 */
public class MfaLoginGateAuthValveTest {

    @Test
    public void nonLoginRequest_continuesPipelineAndWritesNothing() throws Exception {
        StubDecision decision = new StubDecision();
        decision.gated = true; // even if it would be gated, no credentials => nothing to block
        Recorder recorder = new Recorder();
        valve(decision).invoke(authContext(requestWith(null, null), recorder.response), recorder.context());
        assertTrue("a request with no credentials must continue", recorder.invokedNext.get());
        assertNull(recorder.redirectedTo.get());
        assertNull(recorder.errorSent.get());
    }

    @Test
    public void gatedNonWhitelistedPasswordLogin_blocksWithRedirect() throws Exception {
        StubDecision decision = new StubDecision();
        decision.gated = true;
        decision.whitelisted = false;
        decision.distinctLoginUrl = "/sites/mySite/login.html";
        Recorder recorder = new Recorder();
        valve(decision).invoke(authContext(loginPost(), recorder.response), recorder.context());
        assertFalse("a gated password login must NOT continue the pipeline", recorder.invokedNext.get());
        assertEquals("/sites/mySite/login.html", recorder.redirectedTo.get());
        assertNull(recorder.errorSent.get());
    }

    @Test
    public void gatedNonWhitelistedPasswordLogin_blocksWith403WhenNoDistinctUrl() throws Exception {
        StubDecision decision = new StubDecision();
        decision.gated = true;
        decision.whitelisted = false;
        decision.distinctLoginUrl = null; // nowhere distinct to send them
        Recorder recorder = new Recorder();
        valve(decision).invoke(authContext(loginPost(), recorder.response), recorder.context());
        assertFalse(recorder.invokedNext.get());
        assertEquals(Integer.valueOf(HttpServletResponse.SC_FORBIDDEN), recorder.errorSent.get());
        assertNull(recorder.redirectedTo.get());
    }

    @Test
    public void gatedNonWhitelistedPasswordLogin_marksTheRequestAsHandled() throws Exception {
        // This is the signal MfaLoginGateFilter relies on to avoid writing a second terminal
        // response over the one this valve just committed (redirect or 403).
        StubDecision decision = new StubDecision();
        decision.gated = true;
        decision.whitelisted = false;
        decision.distinctLoginUrl = "/sites/mySite/login.html";
        Recorder recorder = new Recorder();
        HttpServletRequest request = loginPost();
        valve(decision).invoke(authContext(request, recorder.response), recorder.context());
        assertEquals(Boolean.TRUE, request.getAttribute(MfaLoginGateAuthValve.ATTR_HANDLED));
    }

    @Test
    public void nonBlockingOutcomes_doNotMarkTheRequestAsHandled() throws Exception {
        // The attribute must stay absent whenever the valve did NOT itself write a terminal
        // response, so the filter keeps evaluating those requests exactly as before (not gated,
        // whitelisted, or decision service unavailable).
        StubDecision notGated = new StubDecision();
        notGated.gated = false;
        HttpServletRequest notGatedRequest = loginPost();
        valve(notGated).invoke(authContext(notGatedRequest, new Recorder().response), new Recorder().context());
        assertNull(notGatedRequest.getAttribute(MfaLoginGateAuthValve.ATTR_HANDLED));

        StubDecision whitelisted = new StubDecision();
        whitelisted.gated = true;
        whitelisted.whitelisted = true;
        HttpServletRequest whitelistedRequest = loginPost();
        valve(whitelisted).invoke(authContext(whitelistedRequest, new Recorder().response), new Recorder().context());
        assertNull(whitelistedRequest.getAttribute(MfaLoginGateAuthValve.ATTR_HANDLED));

        HttpServletRequest noDecisionRequest = loginPost();
        valve(null).invoke(authContext(noDecisionRequest, new Recorder().response), new Recorder().context());
        assertNull(noDecisionRequest.getAttribute(MfaLoginGateAuthValve.ATTR_HANDLED));
    }

    @Test
    public void gatedHeaderCredential_continuesPipelineWhenTheBasicAuthGateIsNotArmed() throws Exception {
        // THE DEFAULT POSTURE, and the reason the switch exists. The header shape reaches every
        // endpoint - the provisioning API and GraphQL included - so with loginGate.gateBasicAuth
        // unset a gated, non-whitelisted Basic credential must still reach the pipeline. Blocking it
        // by default would refuse every integration platform-wide (and the API needed to revert)
        // the moment ONE site enforces a factor.
        StubDecision decision = new StubDecision();
        decision.gated = true;
        decision.whitelisted = false;
        decision.basicAuthGateEnabled = false; // shipped default
        decision.distinctLoginUrl = "/sites/mySite/login.html";
        Recorder recorder = new Recorder();
        valve(decision).invoke(authContext(basicAuthRequest(), recorder.response), recorder.context());
        assertTrue("not armed => a header credential must reach the pipeline", recorder.invokedNext.get());
        assertNull(recorder.errorSent.get());
        assertNull("and must certainly not be redirected", recorder.redirectedTo.get());
    }

    @Test
    public void gatedHeaderCredential_blocksWith403EvenWhenALoginUrlIsConfigured() throws Exception {
        // Armed: a password carried in the Authorization header is a single factor exactly like the
        // form parameters, so it is gated the same way - but the caller is a non-interactive client,
        // so the answer is 403 and never a redirect, even with a distinct login page configured.
        StubDecision decision = new StubDecision();
        decision.gated = true;
        decision.whitelisted = false;
        decision.basicAuthGateEnabled = true;
        decision.distinctLoginUrl = "/sites/mySite/login.html";
        Recorder recorder = new Recorder();
        valve(decision).invoke(authContext(basicAuthRequest(), recorder.response), recorder.context());
        assertFalse("a gated header credential must NOT continue the pipeline", recorder.invokedNext.get());
        assertEquals(Integer.valueOf(HttpServletResponse.SC_FORBIDDEN), recorder.errorSent.get());
        assertNull("a non-interactive caller must not be redirected", recorder.redirectedTo.get());
    }

    @Test
    public void gatedHeaderCredential_isMatchedCaseInsensitively() throws Exception {
        // The gate matches the scheme token case-insensitively, which makes it a strict SUPERSET of
        // every consumer's trigger: Jahia's HttpBasicAuthValve requires the exact "Basic " spelling,
        // Jackrabbit's DAV credentials provider does not. Over-matching is the fail-safe direction.
        StubDecision decision = new StubDecision();
        decision.gated = true;
        decision.basicAuthGateEnabled = true;
        Recorder recorder = new Recorder();
        HttpServletRequest request = requestWithAuthorization("basic YWxpY2U6czNjcmV0");
        valve(decision).invoke(authContext(request, recorder.response), recorder.context());
        assertFalse(recorder.invokedNext.get());
        assertEquals(Integer.valueOf(HttpServletResponse.SC_FORBIDDEN), recorder.errorSent.get());
    }

    @Test
    public void notGatedHeaderCredential_continuesPipeline() throws Exception {
        StubDecision decision = new StubDecision();
        decision.gated = false;
        decision.basicAuthGateEnabled = true; // armed, but nothing enforces => nothing to close
        Recorder recorder = new Recorder();
        valve(decision).invoke(authContext(basicAuthRequest(), recorder.response), recorder.context());
        assertTrue("not gated => the header credential may authenticate", recorder.invokedNext.get());
        assertNull(recorder.errorSent.get());
        assertNull(recorder.redirectedTo.get());
    }

    @Test
    public void whitelistedHeaderCredential_continuesPipeline() throws Exception {
        StubDecision decision = new StubDecision();
        decision.gated = true;
        decision.basicAuthGateEnabled = true;
        decision.whitelisted = true; // the same emergency door as the form-parameter path
        Recorder recorder = new Recorder();
        valve(decision).invoke(authContext(basicAuthRequest(), recorder.response), recorder.context());
        assertTrue(recorder.invokedNext.get());
        assertNull(recorder.errorSent.get());
    }

    @Test
    public void nonPasswordAuthorizationScheme_continuesPipeline() throws Exception {
        // Only a password carried in the header is this gate's business: a token scheme presents no
        // password and carries its own policy, so it continues even while gated AND armed.
        StubDecision decision = new StubDecision();
        decision.gated = true;
        decision.basicAuthGateEnabled = true;
        Recorder recorder = new Recorder();
        HttpServletRequest request = requestWithAuthorization("Bearer abcdef.0123456789");
        valve(decision).invoke(authContext(request, recorder.response), recorder.context());
        assertTrue("a token credential is not gated here", recorder.invokedNext.get());
        assertNull(recorder.errorSent.get());
        assertNull(recorder.redirectedTo.get());
    }

    @Test
    public void bothCredentialShapes_answerInTheHeaderShapeWhenArmed() throws Exception {
        // A request carrying BOTH shapes would be consumed by HttpBasicAuthValve, which sits at the
        // head of the pipeline ahead of LoginEngineAuthValve - so the answer is the one that caller
        // can act on: 403, not a redirect to a login page it will never render.
        StubDecision decision = new StubDecision();
        decision.gated = true;
        decision.basicAuthGateEnabled = true;
        decision.distinctLoginUrl = "/sites/mySite/login.html";
        Recorder recorder = new Recorder();
        HttpServletRequest request = requestWith("alice", "s3cret", "Basic YWxpY2U6czNjcmV0");
        valve(decision).invoke(authContext(request, recorder.response), recorder.context());
        assertFalse(recorder.invokedNext.get());
        assertEquals(Integer.valueOf(HttpServletResponse.SC_FORBIDDEN), recorder.errorSent.get());
        assertNull(recorder.redirectedTo.get());
    }

    @Test
    public void bothCredentialShapes_stillBlockTheFormLoginWhenTheBasicAuthGateIsNotArmed() throws Exception {
        // The unarmed header must not MASK the form shape: a /cms/login POST that also happens to
        // carry a stale Authorization header is still a password-only login attempt, and the
        // unconditional /cms/login block has to keep applying to it.
        StubDecision decision = new StubDecision();
        decision.gated = true;
        decision.basicAuthGateEnabled = false;
        decision.distinctLoginUrl = "/sites/mySite/login.html";
        Recorder recorder = new Recorder();
        HttpServletRequest request = requestWith("alice", "s3cret", "Basic YWxpY2U6czNjcmV0");
        valve(decision).invoke(authContext(request, recorder.response), recorder.context());
        assertFalse("the form-parameter block is not opt-in", recorder.invokedNext.get());
        assertEquals("/sites/mySite/login.html", recorder.redirectedTo.get());
    }

    @Test
    public void activate_registersAtTheHeadOfThePipeline() throws Exception {
        // The position is what puts the gate ahead of BOTH valves that consume a password
        // (HttpBasicAuthValve at the head of the default pipeline, LoginEngineAuthValve after it).
        RecordingPipeline pipeline = new RecordingPipeline();
        Object previousContext = swapSpringContext(contextResolvingBeanTo(pipeline));
        try {
            MfaLoginGateAuthValve valve = new MfaLoginGateAuthValve();
            valve.activate();
            // The literal, not the constant: the assertion is the placement itself, not that the
            // code agrees with its own field.
            assertEquals("the gate must be inserted at the head of the pipeline",
                    Integer.valueOf(0), pipeline.insertedAt.get());
            assertFalse("the gate must never be appended behind the credential valves",
                    pipeline.appended.get());
        } finally {
            swapSpringContext(previousContext);
        }
    }

    @Test
    public void whitelistedClient_continuesPipeline() throws Exception {
        StubDecision decision = new StubDecision();
        decision.gated = true;
        decision.whitelisted = true; // emergency door
        Recorder recorder = new Recorder();
        valve(decision).invoke(authContext(loginPost(), recorder.response), recorder.context());
        assertTrue("a whitelisted client must continue", recorder.invokedNext.get());
        assertNull(recorder.redirectedTo.get());
        assertNull(recorder.errorSent.get());
    }

    @Test
    public void notGatedPasswordLogin_continuesPipeline() throws Exception {
        StubDecision decision = new StubDecision();
        decision.gated = false;
        Recorder recorder = new Recorder();
        valve(decision).invoke(authContext(loginPost(), recorder.response), recorder.context());
        assertTrue("not gated => the login may proceed", recorder.invokedNext.get());
        assertNull(recorder.redirectedTo.get());
        assertNull(recorder.errorSent.get());
    }

    @Test
    public void blockIsIndependentOfHardGateSwitch() throws Exception {
        // The valve must block a gated login even when the hard-gate switch is OFF: the POST bypass
        // must always be closed when a site enforces MFA, regardless of loginGate.enabled.
        StubDecision decision = new StubDecision();
        decision.gated = true;
        decision.whitelisted = false;
        decision.hardGateEnabled = false;
        decision.distinctLoginUrl = "/sites/mySite/login.html";
        Recorder recorder = new Recorder();
        valve(decision).invoke(authContext(loginPost(), recorder.response), recorder.context());
        assertFalse(recorder.invokedNext.get());
        assertEquals("/sites/mySite/login.html", recorder.redirectedTo.get());
    }

    @Test
    public void decisionServiceAbsent_continuesPipeline() throws Exception {
        // The decision service is not available (bundle starting/stopping): the valve cannot decide,
        // so it lets the pipeline proceed (the servlet filter still applies as defense-in-depth).
        Recorder recorder = new Recorder();
        valve(null).invoke(authContext(loginPost(), recorder.response), recorder.context());
        assertTrue(recorder.invokedNext.get());
        assertNull(recorder.redirectedTo.get());
        assertNull(recorder.errorSent.get());
    }

    @Test
    public void nonAuthValveContext_continuesPipeline() throws Exception {
        Recorder recorder = new Recorder();
        valve(new StubDecision()).invoke("not an AuthValveContext", recorder.context());
        assertTrue(recorder.invokedNext.get());
    }

    @Test
    public void formCredentialOnUnrelatedPath_withoutDoLogin_continuesPipeline() throws Exception {
        // FINDING 1 regression: username+password parameters alone must NOT arm the gate.
        // LoginEngineAuthValve only reads them once isLoginRequested() is true (doLogin=true/1, or
        // servletPath=/cms + pathInfo=/login) - an unrelated endpoint carrying fields merely NAMED
        // username/password (common on unrelated Jahia and third-party forms) must reach the
        // pipeline untouched, even while a site enforces MFA and the client is not whitelisted.
        StubDecision decision = new StubDecision();
        decision.gated = true;
        decision.whitelisted = false;
        Recorder recorder = new Recorder();
        HttpServletRequest request = requestOnUnrelatedPath("alice", "s3cret");
        valve(decision).invoke(authContext(request, recorder.response), recorder.context());
        assertTrue("username+password on an unrelated endpoint must not be gated", recorder.invokedNext.get());
        assertNull(recorder.redirectedTo.get());
        assertNull(recorder.errorSent.get());
    }

    @Test
    public void formCredentialWithDoLoginTrue_onAnyPath_isGated() throws Exception {
        // doLogin=true arms LoginEngineAuthValve's trigger regardless of servletPath/pathInfo, so
        // the gate must mirror that: still block even off /cms/login.
        StubDecision decision = new StubDecision();
        decision.gated = true;
        decision.whitelisted = false;
        decision.distinctLoginUrl = "/sites/mySite/login.html";
        Recorder recorder = new Recorder();
        HttpServletRequest request = requestWithDoLogin("alice", "s3cret", "true", "/other", "/somewhere");
        valve(decision).invoke(authContext(request, recorder.response), recorder.context());
        assertFalse("doLogin=true arms the gate regardless of path, mirroring isLoginRequested()",
                recorder.invokedNext.get());
        assertEquals("/sites/mySite/login.html", recorder.redirectedTo.get());
    }

    @Test
    public void formCredentialOnCmsLoginPath_withoutDoLogin_isGated() throws Exception {
        // servletPath=/cms + pathInfo=/login mirrors org.jahia.bin.Login.getMapping(): the genuine
        // /cms/login shape must still be gated even with no explicit doLogin parameter.
        StubDecision decision = new StubDecision();
        decision.gated = true;
        decision.whitelisted = false;
        decision.distinctLoginUrl = "/sites/mySite/login.html";
        Recorder recorder = new Recorder();
        HttpServletRequest request = requestWith("alice", "s3cret", null, null, "/cms", "/login");
        valve(decision).invoke(authContext(request, recorder.response), recorder.context());
        assertFalse("servletPath=/cms + pathInfo=/login is the genuine /cms/login shape",
                recorder.invokedNext.get());
        assertEquals("/sites/mySite/login.html", recorder.redirectedTo.get());
    }

    @Test
    public void formCredentialWithDoLoginOne_onAnyPath_isGated() throws Exception {
        // LoginEngineAuthValveImpl#isLoginRequested also treats the literal "1" as truthy for
        // doLogin - mirror that spelling too.
        StubDecision decision = new StubDecision();
        decision.gated = true;
        decision.whitelisted = false;
        decision.distinctLoginUrl = "/sites/mySite/login.html";
        Recorder recorder = new Recorder();
        HttpServletRequest request = requestWithDoLogin("alice", "s3cret", "1", "/other", "/somewhere");
        valve(decision).invoke(authContext(request, recorder.response), recorder.context());
        assertFalse("doLogin=1 arms the gate the same way as doLogin=true", recorder.invokedNext.get());
        assertEquals("/sites/mySite/login.html", recorder.redirectedTo.get());
    }

    @Test
    public void initializeSetsTheId() {
        MfaLoginGateAuthValve valve = new MfaLoginGateAuthValve();
        valve.initialize();
        assertEquals(MfaLoginGateAuthValve.VALVE_ID, valve.getId());
    }

    @Test
    public void activate_withoutResolvablePipelineBean_doesNotRegisterAndDeactivateIsSafe() throws Exception {
        // U2 (activate-path sub-gap): when SpringContextSingleton cannot resolve the 'authPipeline'
        // bean (here a context whose getBean returns null), activate() must take the no-register
        // branch (log an error, leave authPipeline null) rather than register a half-wired valve —
        // during that window the servlet filter is the only cover — and a subsequent deactivate()
        // must be a safe no-op because nothing was ever registered.
        Object previousContext = swapSpringContext(contextResolvingBeanTo(null));
        try {
            MfaLoginGateAuthValve valve = new MfaLoginGateAuthValve();
            valve.activate();

            Field pipelineField = MfaLoginGateAuthValve.class.getDeclaredField("authPipeline");
            pipelineField.setAccessible(true);
            assertNull("with no resolvable authPipeline bean the valve must NOT register itself",
                    pipelineField.get(valve));

            valve.deactivate(); // must not throw when the valve was never registered
            assertNull(pipelineField.get(valve));
        } finally {
            swapSpringContext(previousContext);
        }
    }

    /** An ApplicationContext whose {@code getBean(String)} returns {@code bean} (everything else null). */
    private static Object contextResolvingBeanTo(Object bean) {
        Class<?> appContext;
        try {
            appContext = Class.forName("org.springframework.context.ApplicationContext");
        } catch (ClassNotFoundException e) {
            throw new AssertionError(e);
        }
        return Proxy.newProxyInstance(appContext.getClassLoader(), new Class<?>[]{appContext},
                (proxy, method, args) -> "getBean".equals(method.getName()) ? bean : null);
    }

    /** Set the SpringContextSingleton's context field to {@code context}, returning the previous value. */
    private static Object swapSpringContext(Object context) throws Exception {
        Class<?> singletonClass = Class.forName("org.jahia.services.SpringContextSingleton");
        Object singleton = singletonClass.getMethod("getInstance").invoke(null);
        Field contextField = singletonClass.getDeclaredField("context");
        contextField.setAccessible(true);
        Object previous = contextField.get(singleton);
        contextField.set(singleton, context);
        return previous;
    }

    // --- Helpers --------------------------------------------------------------------------------

    /** A valve whose OSGi lookup is short-circuited to return the given (possibly null) stub. */
    private static MfaLoginGateAuthValve valve(MfaLoginGateDecision decision) {
        return new MfaLoginGateAuthValve() {
            @Override
            protected MfaLoginGateDecision lookupDecision() {
                return decision;
            }
        };
    }

    private static AuthValveContext authContext(HttpServletRequest request, HttpServletResponse response) {
        return new AuthValveContext(request, response, null);
    }

    /** A POST /cms/login carrying both username and password (a password-login attempt). */
    private static HttpServletRequest loginPost() {
        return requestWith("alice", "s3cret");
    }

    /** A request carrying a password in the Authorization header (alice:s3cret), no form parameters. */
    private static HttpServletRequest basicAuthRequest() {
        return requestWithAuthorization("Basic YWxpY2U6czNjcmV0");
    }

    private static HttpServletRequest requestWith(String username, String password) {
        return requestWith(username, password, null);
    }

    /** A request carrying the given {@code Authorization} header and no form credentials. */
    private static HttpServletRequest requestWithAuthorization(String authorization) {
        return requestWith(null, null, authorization);
    }

    /**
     * Defaults servletPath/pathInfo to the genuine {@code /cms/login} shape
     * (servletPath={@code /cms}, pathInfo={@code /login}), matching {@code getRequestURI()} below,
     * so every pre-existing caller of this overload keeps exercising a real login-requested request.
     */
    private static HttpServletRequest requestWith(String username, String password, String authorization) {
        return requestWith(username, password, authorization, null, "/cms", "/login");
    }

    /** A request carrying username/password parameters on an unrelated endpoint - no doLogin, no /cms/login shape. */
    private static HttpServletRequest requestOnUnrelatedPath(String username, String password) {
        return requestWith(username, password, null, null, "/other", "/somewhere");
    }

    /** A request carrying the {@code doLogin} parameter on an arbitrary servletPath/pathInfo. */
    private static HttpServletRequest requestWithDoLogin(String username, String password, String doLogin,
            String servletPath, String pathInfo) {
        return requestWith(username, password, null, doLogin, servletPath, pathInfo);
    }

    private static HttpServletRequest requestWith(String username, String password, String authorization,
            String doLogin, String servletPath, String pathInfo) {
        // A real backing map for setAttribute/getAttribute, so tests can assert on ATTR_HANDLED.
        Map<String, Object> attributes = new HashMap<>();
        return (HttpServletRequest) Proxy.newProxyInstance(
                MfaLoginGateAuthValveTest.class.getClassLoader(),
                new Class<?>[]{HttpServletRequest.class},
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "getParameter":
                            if ("username".equals(args[0])) {
                                return username;
                            }
                            if ("password".equals(args[0])) {
                                return password;
                            }
                            if ("doLogin".equals(args[0])) {
                                return doLogin;
                            }
                            return null;
                        case "getHeader":
                            return "Authorization".equals(args[0]) ? authorization : null;
                        case "getContextPath":
                            return "";
                        case "getRequestURI":
                            return "/cms/login";
                        case "getServletPath":
                            return servletPath;
                        case "getPathInfo":
                            return pathInfo;
                        case "setAttribute":
                            attributes.put((String) args[0], args[1]);
                            return null;
                        case "getAttribute":
                            return attributes.get(args[0]);
                        default:
                            return null;
                    }
                });
    }

    /** A {@link Pipeline} that records how the valve asked to be inserted. */
    private static final class RecordingPipeline implements Pipeline {
        private final AtomicReference<Integer> insertedAt = new AtomicReference<>();
        private final AtomicBoolean appended = new AtomicBoolean(false);
        private final List<Valve> valves = new ArrayList<>();

        @Override
        public void addValve(int position, Valve valve) {
            insertedAt.set(position);
            valves.add(position, valve);
        }

        @Override
        public void addValve(Valve valve) {
            appended.set(true);
            valves.add(valve);
        }

        @Override
        public Valve[] getValves() {
            return valves.toArray(new Valve[0]);
        }

        @Override
        public void removeValve(Valve valve) {
            valves.remove(valve);
        }

        @Override
        public void initialize() {
            // nothing to initialize in the stub
        }

        @Override
        public void invoke(Object context) {
            // the stub is never driven
        }

        @Override
        public boolean hasValveOfClass(Class<Valve> c) {
            return false;
        }

        @Override
        public Valve getFirstValveOfClass(Class<Valve> c) {
            return null;
        }

        @Override
        public void setEnvironment(Map<String, Object> environment) {
            // no environment in the stub
        }
    }

    /** A stub decision with directly settable answers for the valve's queries. */
    private static final class StubDecision extends MfaLoginGateDecision {
        private boolean gated;
        private boolean whitelisted;
        private boolean hardGateEnabled;
        /** loginGate.gateBasicAuth; false here mirrors the shipped default. */
        private boolean basicAuthGateEnabled;
        private String distinctLoginUrl;

        @Override
        public boolean isGated(HttpServletRequest request) {
            return gated;
        }

        @Override
        public boolean isBasicAuthGateEnabled() {
            return basicAuthGateEnabled;
        }

        @Override
        public boolean isClientWhitelisted(HttpServletRequest request) {
            return whitelisted;
        }

        @Override
        public boolean isHardGateEnabled() {
            return hardGateEnabled;
        }

        @Override
        public String resolveDistinctLoginUrl(HttpServletRequest request) {
            return distinctLoginUrl;
        }
    }

    /** Records whether the pipeline was continued (invokeNext) and any response written. */
    private static final class Recorder {
        private final AtomicBoolean invokedNext = new AtomicBoolean(false);
        private final AtomicReference<String> redirectedTo = new AtomicReference<>();
        private final AtomicReference<Integer> errorSent = new AtomicReference<>();

        private final HttpServletResponse response = (HttpServletResponse) Proxy.newProxyInstance(
                Recorder.class.getClassLoader(),
                new Class<?>[]{HttpServletResponse.class},
                (proxy, method, args) -> {
                    if ("sendRedirect".equals(method.getName())) {
                        redirectedTo.set((String) args[0]);
                    } else if ("sendError".equals(method.getName())) {
                        errorSent.set((Integer) args[0]);
                    }
                    return null;
                });

        private ValveContext context() {
            return new ValveContext() {
                @Override
                public void invokeNext(Object context) throws PipelineException {
                    invokedNext.set(true);
                }

                @Override
                public Map<String, Object> getEnvironment() {
                    return new HashMap<>();
                }
            };
        }
    }
}
