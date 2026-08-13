package org.jahia.modules.upa.mfa.extensions.internal;

import org.jahia.bin.filters.AbstractServletFilter;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

/**
 * Gates Jahia's legacy login endpoint ({@code /cms/login}) while ANY MFA factor enforces enrollment.
 * This servlet filter is <b>defense-in-depth</b>: it stops a {@code GET /cms/login} from reaching
 * the password-only screen on an enforcing site. The decisive block for a {@code POST} happens
 * earlier, in {@link MfaLoginGateAuthValve} - Jahia authenticates a {@code /cms/login} POST in its
 * authentication pipeline (the {@code LoginEngineAuthValve}) which runs BEFORE module servlet
 * filters, so by the time this filter runs a valid POST has already established an authenticated
 * session and the filter can only redirect the response. The valve closes that hole; this filter
 * remains for the credential-free GET case and as a backstop.
 * <p>
 * Scope note: this filter is bound to {@code /cms/login} by its URL patterns, whereas the valve runs
 * on every request in the authentication pipeline. That difference is why the valve's
 * {@code Authorization: Basic} coverage is opt-in ({@code loginGate.gateBasicAuth}) - see
 * {@link MfaLoginGateAuthValve}. Nothing in this filter reacts to that switch.
 * <p>
 * <b>Why this filter must not write to the response a second time.</b> Jahia's own
 * {@code JcrSessionFilter} invokes the authentication pipeline and then continues the SERVLET chain
 * regardless of what the pipeline decided. So when {@link MfaLoginGateAuthValve} blocks a
 * password-only {@code /cms/login} POST - short-circuiting the pipeline and writing a redirect or
 * {@code 403} itself - this filter still runs afterwards on that same request/response pair. Since
 * this filter gates purely on {@link MfaLoginGateDecision#isGated(HttpServletRequest)} +
 * {@link MfaLoginGateDecision#isClientWhitelisted(HttpServletRequest)} (it never looks at
 * credentials), it would independently re-evaluate the SAME decision and try to write a SECOND
 * terminal response on top of the valve's - which throws {@code IllegalStateException} on an
 * already-committed response and surfaces to the client as a bare {@code 500} instead of the
 * {@code 302}/{@code 403} the valve already sent correctly. This filter therefore checks, before
 * anything else: (1) the {@link MfaLoginGateAuthValve#ATTR_HANDLED} request attribute the valve sets
 * the instant it short-circuits - the authoritative "already handled" signal - and (2)
 * {@code response.isCommitted()} as a second, defensive line that also covers any other component
 * that might commit the response ahead of this filter. Neither check is a second gating decision -
 * {@link MfaLoginGateDecision} remains the single source of truth for WHETHER to block; these checks
 * only answer WHETHER a block already happened. Absent either signal (the ordinary {@code GET} case,
 * which carries no credentials and so never reaches the valve's block branch at all) this filter
 * keeps evaluating and acting exactly as before - that GET case is its entire remaining purpose.
 * <p>
 * The actual gating decision (enforcement active, per-site/no-site activation, readiness fail-closed,
 * IP whitelist, configured login URL) lives in the shared {@link MfaLoginGateDecision} component, so
 * the filter and the valve never drift apart. This class only maps the decision onto servlet
 * outcomes:
 * <ul>
 *   <li>not gated -> chain;</li>
 *   <li>whitelisted client -> chain (the operator's emergency/back-office door);</li>
 *   <li><b>explicit hard gate</b> ({@code loginGate.enabled=true}) - 302-redirects to the configured
 *       MFA login page when a DISTINCT one is resolvable, else {@code 403}. It never chains through
 *       to the password-only {@code /cms/login} screen (that is what the hard gate blocks);</li>
 *   <li><b>automatic</b> (gate not enabled) - {@code /cms/login} stays reachable ONLY when the
 *       operator deliberately configured it as the login URL. With a custom MFA login page
 *       configured the request is 302-redirected there; with NO login URL configured at all the
 *       request is rejected with {@code 403} and a configuration-guidance warning.</li>
 * </ul>
 * <p>
 * Registered as an OSGi service of type {@link AbstractServletFilter}: Jahia's {@code CompositeFilter}
 * (mapped at {@code /*} in front of the servlet dispatch) picks it up. A provider that cannot answer
 * (e.g. an unhealthy repository) makes {@link MfaLoginGateDecision} fail <b>closed</b> (block).
 */
@Component(service = AbstractServletFilter.class, immediate = true)
public class MfaLoginGateFilter extends AbstractServletFilter {

    private static final Logger logger = LoggerFactory.getLogger(MfaLoginGateFilter.class);

    /** The shared decision logic; also consumed by {@link MfaLoginGateAuthValve}. */
    private MfaLoginGateDecision decision;

    public MfaLoginGateFilter() {
        setFilterName("MfaLoginGateFilter");
        setUrlPatterns(new String[]{"/cms/login", "/cms/login/*"});
        // Run early among module filters: the whole point is to fire before anything
        // credential-related happens (for the GET case; POST is handled by the valve).
        setOrder(-1f);
    }

    @Reference
    public void setDecision(MfaLoginGateDecision decision) {
        this.decision = decision;
    }

    /**
     * Validate a submitted whitelist value. Kept here (delegating to {@link MfaLoginGateDecision})
     * so the administration mutation ({@code MfaExtensionsConfigSupport}) keeps compiling against
     * its historical entry point after the decision logic moved out.
     */
    public static List<String> parseWhitelist(Object raw) {
        return MfaLoginGateDecision.parseWhitelist(raw);
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // No servlet-level initialization: all state comes from the OSGi configuration.
    }

    @Override
    public void destroy() {
        // Nothing to release.
    }

    /**
     * Whether {@link MfaLoginGateAuthValve} already wrote a terminal response for this exact
     * request - see the class javadoc, "Why this filter must not write to the response a second
     * time". Checked first, before {@link #decision} is consulted at all: there is nothing safe this
     * filter can do to an already-committed response other than leave it alone.
     */
    private static boolean alreadyHandledByTheValve(HttpServletRequest request, ServletResponse response) {
        if (Boolean.TRUE.equals(request.getAttribute(MfaLoginGateAuthValve.ATTR_HANDLED))) {
            logger.debug("MfaLoginGateFilter: MfaLoginGateAuthValve already wrote a terminal response "
                    + "for this request (a password-only POST blocked before authentication) - not "
                    + "re-evaluating the gate a second time");
            return true;
        }
        if (response.isCommitted()) {
            // Defensive: covers any other component that might commit the response ahead of this
            // filter, not just the valve above - a committed response can never be written to again.
            logger.debug("MfaLoginGateFilter: the response is already committed - not writing to it "
                    + "again");
            return true;
        }
        return false;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest)) {
            chain.doFilter(request, response);
            return;
        }
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        if (alreadyHandledByTheValve(httpRequest, response)) {
            return;
        }
        if (!decision.isGated(httpRequest)) {
            chain.doFilter(request, response);
            return;
        }
        if (decision.isClientWhitelisted(httpRequest)) {
            logger.debug("Allowing whitelisted client through the /cms/login gate");
            chain.doFilter(request, response);
            return;
        }
        if (decision.isHardGateEnabled()) {
            // Explicit hard gate: send the user to the configured MFA login page instead of a bare
            // 403 when a DISTINCT one is resolvable. We never chain through to the password-only
            // /cms/login screen here (that is exactly what the hard gate blocks), so if the only
            // configured URL is /cms/login itself - or none is configured - we 403.
            redirectToConfiguredLoginOrForbid(httpRequest, (HttpServletResponse) response);
            return;
        }
        handleAutomaticMode(httpRequest, (HttpServletResponse) response, chain);
    }

    /**
     * Automatic mode (enforcement active, hard gate not enabled): {@code /cms/login} authenticates
     * with the password ALONE, so it stays reachable only when the operator deliberately configured
     * it as the login URL. A configured custom MFA login page is served as a redirect; a missing
     * login URL blocks with configuration guidance: silently allowing the default password-only
     * screen would void the enforced second factor.
     */
    private void handleAutomaticMode(HttpServletRequest request, HttpServletResponse response,
                                     FilterChain chain) throws IOException, ServletException {
        String distinctLogin = decision.resolveDistinctLoginUrl(request);
        if (distinctLogin != null) {
            logger.debug("Rerouting /cms/login to the configured MFA login page (enforcement active)");
            response.sendRedirect(distinctLogin);
            return;
        }
        if (decision.isCmsLoginConfigured(request)) {
            // The operator deliberately chose the default screen as the login URL: respect it.
            chain.doFilter(request, response);
            return;
        }
        logger.warn("Blocked /cms/login access: MFA enforcement is active but no MFA login page is "
                + "configured, so the default password-only screen would bypass the second factor. Configure "
                + "loginUrl (PID org.jahia.modules.mfa.extensions, or the site's MFA administration page), "
                + "set it to /cms/login to deliberately keep the default screen, or whitelist your IP "
                + "(loginGate.ipWhitelist).");
        response.sendError(HttpServletResponse.SC_FORBIDDEN);
    }

    /**
     * Hard-gate block: redirect a gated, non-whitelisted request to the configured MFA login page
     * when a DISTINCT one is available; otherwise reject with {@code 403}. Unlike the automatic mode
     * this never chains through to {@code /cms/login}: the hard gate's contract is to block the
     * password-only screen, so a login URL of {@code /cms/login} itself (or none) leaves {@code 403}
     * as the only safe response.
     */
    private void redirectToConfiguredLoginOrForbid(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String distinctLogin = decision.resolveDistinctLoginUrl(request);
        if (distinctLogin != null) {
            logger.debug("Hard gate: rerouting /cms/login to the configured MFA login page");
            response.sendRedirect(distinctLogin);
            return;
        }
        logger.warn("Blocked /cms/login access (MFA enrollment enforced and IP not whitelisted; "
                + "no distinct MFA login page is configured to redirect to - set loginUrl on PID "
                + "org.jahia.modules.mfa.extensions or the site's MFA administration page)");
        response.sendError(HttpServletResponse.SC_FORBIDDEN);
    }
}
