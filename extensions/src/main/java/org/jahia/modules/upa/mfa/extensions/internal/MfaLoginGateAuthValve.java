package org.jahia.modules.upa.mfa.extensions.internal;

import org.apache.commons.lang3.StringUtils;
import org.jahia.params.valves.AuthValveContext;
import org.jahia.params.valves.BaseAuthValve;
import org.jahia.pipelines.Pipeline;
import org.jahia.pipelines.PipelineException;
import org.jahia.pipelines.valves.ValveContext;
import org.jahia.services.SpringContextSingleton;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Applies the MFA gate to a password login inside Jahia's authentication pipeline: a Jahia
 * authentication valve inserted at the head of that pipeline, so that it runs ahead of every valve
 * that consumes a password.
 * <p>
 * <b>Which credential shapes the gate covers.</b> A password reaches the pipeline in two shapes, and
 * a different valve consumes each one: the {@code username}/{@code password} form parameters of a
 * {@code /cms/login} POST ({@code LoginEngineAuthValve}), and an {@code Authorization: Basic} header
 * on any endpoint ({@code HttpBasicAuthValve}, enabled by default). Both are a single factor, so both
 * CAN be gated here. Sitting at position 0 is what makes that possible - the gate is ahead of both
 * consumers, whichever one a request is heading for. Token credentials ({@code TokenAuthValve},
 * personal access tokens) are a different policy question and are not gated here.
 * <p>
 * The two shapes are NOT armed alike:
 * <ul>
 *   <li>the <b>form parameters</b> are gated unconditionally whenever a site enforces a factor -
 *       that shape belongs to one interactive endpoint, and letting it through is the MFA bypass
 *       this component exists to close;</li>
 *   <li>the <b>{@code Authorization: Basic} header</b> is gated only when the operator sets
 *       {@code loginGate.gateBasicAuth=true} (default {@code false}; see
 *       {@link MfaLoginGateDecision#isBasicAuthGateEnabled()}). That shape belongs to no particular
 *       endpoint: it is what every script, integration, CI job and WebDAV client sends, so gating it
 *       refuses the whole machine-facing surface - the provisioning API included - the moment ONE
 *       site enforces a factor. Since the IP whitelist fails closed behind a reverse proxy
 *       (GHSA-4v3g-mcmj-83fp), an always-on version of this could leave an operator with no HTTP
 *       route back to the setting that caused it. Opt-in makes that a deliberate posture.</li>
 * </ul>
 * A blocked header credential is answered with {@code 403} rather than a redirect: the caller is a
 * non-interactive client, which has no login page to follow.
 * <p>
 * <b>Why a valve and not just the servlet filter?</b> Jahia authenticates a {@code /cms/login} POST
 * inside its authentication pipeline, and that pipeline runs BEFORE module servlet filters. So a
 * POST carrying a valid username/password establishes an authenticated session BEFORE
 * {@link MfaLoginGateFilter} ever runs - the filter can then only redirect the <i>response</i>,
 * while the session is already authenticated. The result is that a password-only {@code /cms/login}
 * POST fully bypasses MFA on an enforcing site (the filter appears to gate GET only because a GET
 * carries no credentials to authenticate). Running as a valve at the head of the pipeline, this
 * component can short-circuit it and block the login BEFORE any authentication happens. The servlet
 * filter stays as defense-in-depth (mainly the GET case); both share {@link MfaLoginGateDecision} so
 * they never drift apart.
 * <p>
 * Pipeline protocol: {@link ValveContext#invokeNext(Object)} CONTINUES the pipeline (let the login
 * proceed); NOT calling it short-circuits, and this valve then writes the response itself (a redirect
 * to the configured MFA login page, or {@code 403}).
 * <p>
 * The block is independent of the {@code loginGate.enabled} hard-gate switch: that switch only tunes
 * the servlet filter's GET behavior, but the password-login POST bypass must ALWAYS be closed when a
 * site enforces MFA. Only the IP whitelist (the operator's emergency door) and the absence of
 * enforcement let a login through.
 * <p>
 * <b>Registration:</b> this is a Declarative Services component (the module has no Spring context).
 * On {@code @Activate} it resolves Jahia's {@code authPipeline} bean via {@link SpringContextSingleton}
 * and inserts itself at position 0 using the {@link BaseAuthValve} helper; on {@code @Deactivate} it
 * removes itself. An absolute position is deliberate: the helper's positionBefore/positionAfter form
 * appends the valve at the END of the pipeline when it cannot resolve the named valve's id - behind
 * every credential consumer, which for a gate is the one placement that must not happen. (It still
 * extends {@link BaseAuthValve} for the
 * id/enabled bookkeeping and the add/remove helpers; the Spring auto-registration base is not used
 * because Jahia does not build a Spring context for this bnd/DS bundle.)
 */
@Component(service = MfaLoginGateAuthValve.class, immediate = true)
public class MfaLoginGateAuthValve extends BaseAuthValve {

    private static final Logger logger = LoggerFactory.getLogger(MfaLoginGateAuthValve.class);

    static final String VALVE_ID = "MfaLoginGateAuthValve";
    /** Jahia core Spring bean id for the authentication pipeline. */
    static final String AUTH_PIPELINE_BEAN = "authPipeline";
    /**
     * Insert at the head of the pipeline. The property this buys is being ahead of BOTH valves that
     * consume a password ({@code HttpBasicAuthValve}, {@code LoginEngineAuthValve}) - not literally
     * being index 0 forever: another module can insert at 0 later and push this valve to 1. That is
     * harmless and, for {@code personal-api-tokens}, desirable - its token valve authenticates and
     * short-circuits before this gate is reached, which is what makes "use a personal API token
     * instead" work as advice.
     */
    static final int VALVE_POSITION = 0;

    private static final String PARAM_USERNAME = "username";
    private static final String PARAM_PASSWORD = "password";
    private static final String HEADER_AUTHORIZATION = "Authorization";
    /** Lower-cased: the scheme token is case-insensitive (RFC 7235), so the gate matches it that way. */
    private static final String SCHEME_BASIC = "basic ";

    private MfaLoginGateDecision decision;
    private Pipeline authPipeline;
    /** One-shot latch for the header-block WARN; see {@link #blockHeaderCredential}. Reset on activation. */
    private final AtomicBoolean headerBlockWarned = new AtomicBoolean(false);

    @Reference
    public void setDecision(MfaLoginGateDecision decision) {
        this.decision = decision;
    }

    @Activate
    public void activate() {
        initialize();
        headerBlockWarned.set(false); // a redeploy earns a fresh loud line
        Object bean = SpringContextSingleton.getBean(AUTH_PIPELINE_BEAN);
        if (bean instanceof Pipeline) {
            authPipeline = (Pipeline) bean;
            addValve(authPipeline, VALVE_POSITION, null, null);
            logger.info("MFA login gate auth valve registered at position {} (gates a password login - "
                    + "form parameters or Authorization header - before authentication while a site "
                    + "enforces MFA)", VALVE_POSITION);
        } else {
            logger.error("Could not resolve the '{}' pipeline bean - the MFA password-login gate is NOT "
                    + "active in the authentication pipeline. Got: {}", AUTH_PIPELINE_BEAN, bean);
        }
    }

    @Deactivate
    public void deactivate() {
        if (authPipeline != null) {
            removeValve(authPipeline);
            authPipeline = null;
            logger.info("MFA login gate auth valve unregistered from the auth pipeline");
        }
    }

    @Override
    public void initialize() {
        setId(VALVE_ID);
        setEnabled(true);
    }

    @Override
    public void invoke(Object context, ValveContext valveContext) throws PipelineException {
        if (!(context instanceof AuthValveContext)) {
            valveContext.invokeNext(context);
            return;
        }
        AuthValveContext authContext = (AuthValveContext) context;
        HttpServletRequest request = authContext.getRequest();
        HttpServletResponse response = authContext.getResponse();

        // Mirror the credential triggers of the two valves that consume a password:
        // LoginEngineAuthValve authenticates when BOTH the username and password parameters are
        // present, HttpBasicAuthValve when the Authorization header carries the Basic scheme. A
        // request with neither shape presents no password - the gate has nothing to evaluate, so let
        // the pipeline continue.
        boolean formCredential = isPasswordLoginAttempt(request);
        boolean headerShape = isHeaderCredentialAttempt(request);
        if (!formCredential && !headerShape) {
            valveContext.invokeNext(context);
            return;
        }

        MfaLoginGateDecision currentDecision = lookupDecision();
        if (currentDecision == null) {
            // The decision component is not bound yet (bundle starting / stopping). We cannot decide,
            // so allow the pipeline to proceed: the servlet filter still covers this endpoint. Logged
            // as a warning because, during this window, a password-only POST is not blocked here.
            logger.warn("MFA login gate auth valve: decision component unavailable, cannot evaluate the "
                    + "/cms/login gate - letting the login proceed (servlet filter still applies)");
            valveContext.invokeNext(context);
            return;
        }

        // The header shape is OPT-IN (loginGate.gateBasicAuth): unlike the form parameters it is not
        // confined to /cms/login, so gating it refuses every non-interactive client on every
        // endpoint. Not armed => this valve has nothing to say about a header-only request.
        boolean headerCredential = headerShape && currentDecision.isBasicAuthGateEnabled();
        if (!formCredential && !headerCredential) {
            valveContext.invokeNext(context);
            return;
        }

        // The emergency door: a whitelisted client is always let through (matches the filter).
        if (currentDecision.isClientWhitelisted(request)) {
            valveContext.invokeNext(context);
            return;
        }

        // The decisive block: a gated password login must NOT authenticate. Short-circuit the
        // pipeline (do not invokeNext) and write the response ourselves. When a request carries BOTH
        // shapes the header answer wins, because HttpBasicAuthValve sits at the head of the pipeline
        // and is the valve that would actually have consumed such a request.
        if (currentDecision.isGated(request)) {
            if (headerCredential) {
                blockHeaderCredential(request, response);
            } else {
                block(currentDecision, request, response);
            }
            return;
        }

        valveContext.invokeNext(context);
    }

    /**
     * Block a credential presented in the {@code Authorization} header: always {@code 403}, never a
     * redirect. The caller is a non-interactive client (a script, an integration), so a login page is
     * not something it can follow; a status code is the only answer it can act on. Non-interactive
     * callers authenticate with a personal access token, which carries its own policy.
     * <p>
     * Logged at DEBUG per request, with the target so an operator can tell WHICH integration broke:
     * this branch fires on any endpoint for any unauthenticated caller, so a per-request WARN would
     * hand that caller a log-amplification lever. The one-shot WARN below is the loud line instead -
     * it names the switch and the way out exactly once per activation, which is what an operator
     * chasing a newly-403ing integration actually needs.
     */
    private void blockHeaderCredential(HttpServletRequest request, HttpServletResponse response)
            throws PipelineException {
        if (headerBlockWarned.compareAndSet(false, true)) {
            logger.warn("MFA login gate auth valve: refusing passwords presented in the {} header while MFA "
                    + "enrollment is enforced ({}=true). Non-interactive clients must authenticate with a "
                    + "personal API token instead. Set {}=false on PID org.jahia.modules.mfa.extensions to "
                    + "revert. Further occurrences are logged at DEBUG.",
                    HEADER_AUTHORIZATION, MfaLoginGateDecision.CONFIG_GATE_BASIC_AUTH,
                    MfaLoginGateDecision.CONFIG_GATE_BASIC_AUTH);
        }
        logger.debug("MFA login gate auth valve: blocked a password presented in the {} header for {} "
                + "(enforced, IP not whitelisted)", HEADER_AUTHORIZATION, request.getRequestURI());
        forbid(response);
    }

    /**
     * Block the login: redirect to the configured MFA login page when a distinct one is resolvable,
     * else {@code 403}. Never chains the pipeline - returning without {@code invokeNext} stops the
     * authentication.
     */
    private void block(MfaLoginGateDecision currentDecision, HttpServletRequest request, HttpServletResponse response)
            throws PipelineException {
        String distinctLogin = currentDecision.resolveDistinctLoginUrl(request);
        if (distinctLogin == null) {
            logger.warn("MFA login gate auth valve: blocked password-only /cms/login (MFA enrollment "
                    + "enforced and IP not whitelisted; no distinct MFA login page configured to redirect "
                    + "to - set loginUrl on PID org.jahia.modules.mfa.extensions or the site's MFA "
                    + "administration page)");
            forbid(response);
            return;
        }
        logger.debug("MFA login gate auth valve: blocking password-only /cms/login, redirecting to "
                + "the configured MFA login page");
        try {
            response.sendRedirect(distinctLogin);
        } catch (IOException e) {
            throw new PipelineException("Failed to write the MFA login gate block response", e);
        }
    }

    /** Reject the request with {@code 403}, the gate's terminal answer. */
    private static void forbid(HttpServletResponse response) throws PipelineException {
        try {
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
        } catch (IOException e) {
            throw new PipelineException("Failed to write the MFA login gate block response", e);
        }
    }

    /** A {@code /cms/login} POST is a password-login attempt only when BOTH credentials are present. */
    private static boolean isPasswordLoginAttempt(HttpServletRequest request) {
        return StringUtils.isNotEmpty(request.getParameter(PARAM_USERNAME))
                && StringUtils.isNotEmpty(request.getParameter(PARAM_PASSWORD));
    }

    /**
     * Whether the request presents a password in the {@code Authorization} header - the shape
     * {@code HttpBasicAuthValve} consumes, on any endpoint. Matched case-insensitively on the scheme
     * token, which RFC 7235 defines as case-insensitive, so the gate covers every spelling a client
     * may send.
     */
    private static boolean isHeaderCredentialAttempt(HttpServletRequest request) {
        String authorization = request.getHeader(HEADER_AUTHORIZATION);
        return authorization != null && authorization.toLowerCase(Locale.ROOT).startsWith(SCHEME_BASIC);
    }

    /** The bound decision component. Overridable seam so unit tests can inject a stub. */
    protected MfaLoginGateDecision lookupDecision() {
        return decision;
    }

    // A valve's identity in the pipeline is its id (see BaseAuthValve); the injected decision and
    // pipeline are runtime wiring, not identity. Delegate so equals/hashCode stay id-based.
    @Override
    public boolean equals(Object obj) {
        return super.equals(obj);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }
}
