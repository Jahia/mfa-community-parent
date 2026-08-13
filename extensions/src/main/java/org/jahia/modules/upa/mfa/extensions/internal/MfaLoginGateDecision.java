package org.jahia.modules.upa.mfa.extensions.internal;

import org.apache.commons.lang3.StringUtils;
import org.jahia.modules.upa.mfa.extensions.MfaGlobalPolicy;
import org.jahia.modules.upa.mfa.extensions.MfaSiteConfigChangeListener;
import org.jahia.modules.upa.mfa.extensions.MfaSiteConfigService;
import org.jahia.modules.upa.mfa.extensions.MfaSiteProvider;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

/**
 * The shared, request-time decision logic that gates a password login while ANY MFA factor
 * enforces enrollment. It is consulted by BOTH access points that apply the gate:
 * <ul>
 *   <li>{@link MfaLoginGateAuthValve} - a Jahia authentication valve registered at the HEAD of the
 *       authentication pipeline, which is the only place that can block a {@code /cms/login}
 *       <b>POST</b> before a session is established (the servlet filter runs too late for POST -
 *       see that class). The valve also covers a password carried in an {@code Authorization: Basic}
 *       header, but ONLY when the operator arms {@code loginGate.gateBasicAuth} - that shape reaches
 *       every endpoint, so it is opt-in;</li>
 *   <li>{@link MfaLoginGateFilter} - the servlet filter that remains as defense-in-depth on
 *       {@code /cms/login}, mainly effective for GET requests with no credentials to authenticate.</li>
 * </ul>
 * <p>
 * The MFA challenge runs in UPA's GraphQL {@code initiate} flow (used by the factor login UI) -
 * but {@code /cms/login} authenticates through Jahia's classic username/password valve and never
 * consults MFA factors. On a site that <i>enforces</i> enrollment, that endpoint is therefore a
 * complete second-factor bypass. The gating contract:
 * <ul>
 *   <li>nothing is gated while the global enforcement policy ({@link MfaGlobalPolicy}) lists no
 *       factors;</li>
 *   <li>once enforcement IS active, a request is gated when ANY site has one of the enforced
 *       factors enabled - {@code /cms/login} authenticates GLOBALLY (the session it hands out is
 *       valid on every site), so a single such site is enough to make the endpoint a bypass
 *       vector;</li>
 *   <li>a site context (the {@code site} request parameter or the {@code siteKey} request
 *       attribute) may only ADD gating, never remove it - see {@link #isGated};</li>
 *   <li>gated requests are exempt when the client IP matches the configured whitelist, so
 *       operators keep an emergency/back-office door (e.g. their VPN range).</li>
 * </ul>
 * <p>
 * <b>The site context must never NARROW the decision:</b> this gate runs on a fully
 * unauthenticated endpoint, so every input it reads is attacker-controlled. Resolving the site
 * from the {@code site} REQUEST PARAMETER and then asking only "does THAT site enforce?" turned
 * the gate into an opt-out: {@code POST /cms/login} with {@code &site=<any-name-not-enforcing>}
 * (a site where the factor is not enabled, or a site key that does not exist at all - the
 * parameter was only syntax-checked against {@link #SITE_KEY_PATTERN}, never against the set of
 * real sites) reported "not enforcing" and let the classic password valve complete a full
 * password-only authentication. The site is therefore now only a HINT that may raise, never
 * lower, the answer (see {@link #resolveSiteHint}).
 * <p>
 * This component is factor-agnostic: it discovers per-site activation through every registered
 * {@link MfaSiteProvider} (TOTP, WebAuthn, ...) and intersects it with the global policy. It
 * therefore has no compile-time dependency on any individual factor module.
 * <p>
 * The client IP is taken from the FIRST entry of the {@code X-Forwarded-For} header when present
 * (the original client, by convention), falling back to the raw socket peer address - but ONLY
 * when {@code loginGate.trustForwardedFor} is {@code true} (NOT the default; see SEC-135).
 * <b>Trust caveat:</b> {@code X-Forwarded-For} is client-spoofable - only trust it behind a
 * reverse proxy that overwrites (or sanitizes) the header, otherwise an attacker can impersonate
 * a whitelisted IP with a single forged header. Set {@code loginGate.trustForwardedFor=false} to
 * always use the raw socket peer address instead.
 * <p>
 * <b>{@code request.getRemoteAddr()} is NOT reliable for this even when {@code false}
 * (GHSA-4v3g-mcmj-83fp):</b> the Jahia EE image ships Tomcat's {@code RemoteIpValve} enabled by
 * default, and when the immediate TCP peer falls in its (permissive-by-default) {@code
 * internalProxies} range that valve overwrites {@code getRemoteAddr()} with the
 * {@code X-Forwarded-For} value BEFORE this code ever runs - making the "safe" fallback just as
 * spoofable as trusting the header directly. Unlike some reverse-proxy integrations, Tomcat's
 * {@code RemoteIpValve} does NOT preserve the pre-rewrite address anywhere accessible afterwards
 * (verified against the shipped Tomcat 9 build: it captures {@code getRemoteAddr()} into its
 * access-log attributes only AFTER the rewrite, so those read back the same spoofed value) - so
 * this code cannot recover a trustworthy raw peer once that valve has run. Instead
 * {@link #resolveClientIp} detects the rewrite itself via the {@code
 * org.apache.tomcat.request.forwarded} request attribute the valve sets whenever it resolved the
 * address from a header, and - with {@code trustForwardedFor=false} - refuses to treat that
 * address as a verified socket peer for the whitelist, failing CLOSED (not whitelisted) rather
 * than trusting a value it cannot verify. See {@link #wasAddressRewrittenFromForwardedHeader}.
 * <p>
 * Configuration (PID {@code org.jahia.modules.mfa.extensions}, hot-reloaded via {@code @Modified}):
 * <ul>
 *   <li>{@code loginGate.enabled} - the explicit HARD gate switch (consumed by the servlet filter
 *       to choose between redirect-or-403 and the automatic mode), default {@code false}. Note the
 *       valve blocks a gated password login regardless of this switch: the POST bypass must always
 *       be closed when a site enforces MFA.</li>
 *   <li>{@code loginGate.ipWhitelist} - comma-separated IPv4/IPv6 addresses or CIDR blocks
 *       (e.g. {@code 203.0.113.7, 10.0.0.0/8, 2001:db8::/32}).</li>
 *   <li>{@code loginGate.trustForwardedFor} - whether to read the client IP from the
 *       {@code X-Forwarded-For} header, default {@code false} (spoof-proof socket address; SEC-135).
 *       Only enable behind a reverse proxy that overwrites the header.</li>
 *   <li>{@code loginGate.gateBasicAuth} - whether the valve also gates a password presented in an
 *       {@code Authorization: Basic} header, default {@code false}. Unlike the {@code /cms/login}
 *       form shape this reaches EVERY endpoint (the provisioning API, GraphQL, the tools, WebDAV),
 *       so arming it refuses every Basic-auth integration platform-wide while enforcement is
 *       active. Opt-in for exactly that reason; see {@link #isBasicAuthGateEnabled()}.</li>
 * </ul>
 * <p>
 * A provider that cannot answer (e.g. an unhealthy repository) throws, and the gate fails
 * <b>closed</b> (block): this is an access-control decision, and if the backend is unhealthy the
 * login could not complete anyway.
 */
@Component(service = {MfaLoginGateDecision.class, MfaSiteConfigChangeListener.class}, immediate = true,
        configurationPid = "org.jahia.modules.mfa.extensions")
public class MfaLoginGateDecision implements MfaSiteConfigChangeListener {

    private static final Logger logger = LoggerFactory.getLogger(MfaLoginGateDecision.class);

    static final String CONFIG_GATE_ENABLED = "loginGate.enabled";
    static final String CONFIG_GATE_WHITELIST = "loginGate.ipWhitelist";
    static final String CONFIG_TRUST_FORWARDED_FOR = "loginGate.trustForwardedFor";
    static final String CONFIG_GATE_BASIC_AUTH = "loginGate.gateBasicAuth";

    private static final String HEADER_X_FORWARDED_FOR = "X-Forwarded-For";
    /**
     * Request attribute Tomcat's {@code org.apache.catalina.valves.RemoteIpValve} sets to
     * {@code Boolean.TRUE} whenever it resolved {@code getRemoteAddr()} from the (attacker-facing)
     * {@code X-Forwarded-For}/{@code proxiesHeader} pair - i.e. exactly when {@code
     * getRemoteAddr()} is no longer a verified socket peer address (GHSA-4v3g-mcmj-83fp). The
     * valve does not expose the pre-rewrite address anywhere afterwards, so this flag - not a
     * recovered "true" address - is what {@link #resolveClientIp} relies on to fail closed.
     * Referenced by name (not a Tomcat API constant) to avoid a compile dependency on Tomcat.
     */
    private static final String ATTR_TOMCAT_REQUEST_FORWARDED = "org.apache.tomcat.request.forwarded";
    private static final String PARAM_SITE = "site";
    private static final String ATTR_SITE_KEY = "siteKey";

    /** Valid Jahia site keys - also prevents JCR path traversal via the user-supplied parameter. */
    private static final Pattern SITE_KEY_PATTERN = Pattern.compile("[A-Za-z0-9_-]+");
    private static final Pattern IPV4_PATTERN = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}");
    /** IPv6 literal (possibly v4-mapped). The ':' requirement rules out hostnames - labels cannot contain it. */
    private static final Pattern IPV6_PATTERN = Pattern.compile("[0-9a-fA-F:.]*:[0-9a-fA-F:.]*");

    /** How long the "is any site enforcing?" answer is reused before re-querying the providers. */
    private static final long ENFORCING_CACHE_MILLIS = 60_000L;

    private final AtomicBoolean gateEnabled = new AtomicBoolean(false);
    /**
     * Trust the {@code X-Forwarded-For} header for the client IP. Default {@code false}: the header is
     * client-spoofable, so the whitelist would otherwise be bypassable with a single forged header
     * (SEC-135). Only enable behind a reverse proxy that overwrites {@code X-Forwarded-For}.
     */
    private final AtomicBoolean trustForwardedFor = new AtomicBoolean(false);
    /**
     * Gate a password presented in an {@code Authorization: Basic} header. Default {@code false}:
     * that shape is not confined to {@code /cms/login} - it is what every non-interactive client
     * uses on EVERY endpoint - so arming it refuses the provisioning API, GraphQL, the tools and
     * WebDAV platform-wide as soon as one site enforces a factor. Opt-in, like the hard gate.
     */
    private final AtomicBoolean gateBasicAuth = new AtomicBoolean(false);
    private final AtomicReference<List<String>> whitelist = new AtomicReference<>(Collections.emptyList());
    private final AtomicReference<EnforcingCache> enforcingCache = new AtomicReference<>();

    /** Every registered factor's per-site activation view. Read-heavy on the request path -> copy-on-write. */
    private final List<MfaSiteProvider> siteProviders = new CopyOnWriteArrayList<>();

    /** The global enforcement policy (same bundle, same configuration PID). */
    private MfaGlobalPolicy globalPolicy;

    /** Resolves the configured login URL (per-site -> global). */
    private MfaLoginLogoutProvider loginLogoutProvider;

    /**
     * The per-site config service; consulted ONLY for its {@link MfaSiteConfigService#isReady()}
     * readiness flag so BOTH gating paths (resolved-site and no-site) can fail CLOSED during the
     * startup window before FileInstall/the eager scan has populated the map. May be {@code null}
     * in a unit test that does not exercise the readiness path (treated as ready).
     */
    private MfaSiteConfigService siteConfigService;

    @Reference
    public void setGlobalPolicy(MfaGlobalPolicy globalPolicy) {
        this.globalPolicy = globalPolicy;
    }

    @Reference
    public void setLoginLogoutProvider(MfaLoginLogoutProvider loginLogoutProvider) {
        this.loginLogoutProvider = loginLogoutProvider;
    }

    @Reference
    public void setSiteConfigService(MfaSiteConfigService siteConfigService) {
        this.siteConfigService = siteConfigService;
    }

    @Reference(service = MfaSiteProvider.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC)
    public void bindSiteProvider(MfaSiteProvider provider) {
        siteProviders.add(provider);
        enforcingCache.set(null); // a new factor may change the global enforcement answer
    }

    public void unbindSiteProvider(MfaSiteProvider provider) {
        siteProviders.remove(provider);
        enforcingCache.set(null);
    }

    /**
     * Drop the cached "is any site enforcing?" answer so the next no-site {@code /cms/login} request
     * re-queries the providers. Invoked when the per-site configuration changes (see
     * {@link #onSiteConfigChanged()}): enabling a factor on the FIRST site would otherwise leave the
     * stale "not enforcing" answer cached for up to {@value #ENFORCING_CACHE_MILLIS} ms, a bounded
     * fail-OPEN window in this security gate (U8). Public so the same-bundle
     * {@link MfaSiteConfigService} can trigger it across the internal/non-internal package split.
     */
    public void invalidateEnforcingCache() {
        enforcingCache.set(null);
    }

    /**
     * {@link MfaSiteConfigChangeListener} callback: the per-site config just changed, so the cached
     * enforcement answer may be stale — drop it immediately (closes the U8 fail-open window). This
     * component is wired to the config service as an <em>optional/dynamic</em> reverse reference, so
     * this fires only once both components are up and never forms an activation cycle.
     */
    @Override
    public void onSiteConfigChanged() {
        invalidateEnforcingCache();
    }

    @Activate
    @Modified
    public void activate(Map<String, Object> properties) {
        boolean enabled = parseFlag(properties, CONFIG_GATE_ENABLED);
        List<String> entries = parseWhitelist(properties == null ? null : properties.get(CONFIG_GATE_WHITELIST));
        boolean trustXff = parseFlag(properties, CONFIG_TRUST_FORWARDED_FOR);
        boolean basicAuth = parseFlag(properties, CONFIG_GATE_BASIC_AUTH);
        gateEnabled.set(enabled);
        whitelist.set(entries);
        trustForwardedFor.set(trustXff);
        gateBasicAuth.set(basicAuth);
        enforcingCache.set(null); // settings may have changed semantics; re-query on next hit
        logger.info("MFA /cms/login gate {} ({} whitelist entr{})",
                enabled ? "ENABLED" : "disabled", entries.size(), entries.size() == 1 ? "y" : "ies");
        if (!entries.isEmpty() && trustXff) {
            logger.info("MFA /cms/login gate: a whitelist is set and {} is true - the client IP is taken "
                    + "from X-Forwarded-For, which is client-spoofable. Only keep this enabled behind a "
                    + "reverse proxy that overwrites the header, or set {}=false.",
                    CONFIG_TRUST_FORWARDED_FOR, CONFIG_TRUST_FORWARDED_FOR);
        }
        if (basicAuth) {
            logger.warn("MFA gate: {} is TRUE - while a site enforces a factor, EVERY request carrying an "
                    + "Authorization: Basic header is refused with 403, on every endpoint (provisioning API, "
                    + "GraphQL, tools, WebDAV), not just /cms/login. Non-interactive clients must switch to a "
                    + "personal API token. Keep a working way back in: behind a reverse proxy (or Tomcat's "
                    + "RemoteIpValve) {} only matches when {} is also true, otherwise the whitelist fails "
                    + "closed and the only way to revert this key is editing the .cfg file on disk.",
                    CONFIG_GATE_BASIC_AUTH, CONFIG_GATE_WHITELIST, CONFIG_TRUST_FORWARDED_FOR);
        }
    }

    /**
     * Read a boolean key, defaulting to {@code false} when absent or unparseable - the safe default
     * for every switch on this PID ({@code loginGate.enabled}, {@code loginGate.trustForwardedFor}
     * (SEC-135), {@code loginGate.gateBasicAuth}): each of them WIDENS what the gate blocks or what
     * it trusts, so "not configured" must never mean "on".
     */
    private static boolean parseFlag(Map<String, Object> properties, String key) {
        if (properties == null) {
            return false;
        }
        Object raw = properties.get(key);
        return raw != null && Boolean.parseBoolean(String.valueOf(raw));
    }

    /**
     * Parse the comma-separated whitelist, dropping (and logging) syntactically invalid entries.
     * Public so the administration mutation can validate submitted values (the class itself is
     * internal/unexported).
     */
    public static List<String> parseWhitelist(Object raw) {
        if (raw == null || StringUtils.isBlank(raw.toString())) {
            return Collections.emptyList();
        }
        List<String> entries = new ArrayList<>();
        for (String part : raw.toString().split(",")) {
            String entry = part.trim();
            if (entry.isEmpty()) {
                continue;
            }
            if (isValidWhitelistEntry(entry)) {
                entries.add(entry);
            } else {
                logger.warn("Ignoring invalid {} entry: '{}' (expected an IPv4/IPv6 address or CIDR block)",
                        CONFIG_GATE_WHITELIST, entry);
            }
        }
        return Collections.unmodifiableList(entries);
    }

    /** Whether the explicit HARD gate switch ({@code loginGate.enabled}) is on. */
    public boolean isHardGateEnabled() {
        return gateEnabled.get();
    }

    /**
     * Whether a password presented in an {@code Authorization: Basic} header is gated
     * ({@code loginGate.gateBasicAuth}, default {@code false}).
     * <p>
     * Left to the operator rather than always-on, unlike the {@code /cms/login} POST block. That
     * block is bounded to one interactive endpoint whose blocked callers have a login page to
     * follow; the header shape is bounded by nothing - it is the credential every script,
     * integration and CI job uses, on every endpoint. Arming it with one site enforcing a factor
     * therefore 403s the whole machine-facing surface at once, and the emergency door does not
     * always answer: behind Tomcat's {@code RemoteIpValve} (shipped enabled on the Jahia EE image)
     * the whitelist fails CLOSED with {@code trustForwardedFor=false} (GHSA-4v3g-mcmj-83fp), so an
     * operator can arm this and lose the very API needed to disarm it. Opting in is what makes that
     * a decision rather than a surprise.
     */
    public boolean isBasicAuthGateEnabled() {
        return gateBasicAuth.get();
    }

    /**
     * Whether this request must be gated: global enforcement is active AND at least one site has
     * one of the enforced factors enabled. The request's site context is consulted FIRST, but
     * purely as a widening hint - the two answers are OR-ed, never substituted:
     * <ul>
     *   <li>the (uncached) per-site answer closes the bounded {@value #ENFORCING_CACHE_MILLIS} ms
     *       staleness window of the any-site cache for a request that names an enforcing site;</li>
     *   <li>the any-site answer is always evaluated when the per-site one is negative, so an
     *       attacker-supplied {@code site} parameter naming a non-enforcing (or non-existent) site
     *       can no longer turn the gate OFF - an unauthenticated request must never be able to
     *       narrow an access-control decision.</li>
     * </ul>
     * Fails CLOSED when a provider cannot answer (throws) and while the per-site configuration is
     * not ready yet.
     */
    public boolean isGated(HttpServletRequest request) {
        if (!globalPolicy.isEnforcementActive()) {
            return false;
        }
        // During the startup window the per-site config map may not be populated yet (FileInstall is
        // async) and the eager scan may not have run, so BOTH the resolved-site and the no-site
        // branches below could report "not enforcing" off an empty map and let /cms/login through
        // password-only - a fail-OPEN bypass. Enforcement is active here, so fail CLOSED until the
        // config service is ready, regardless of whether the request carries a site context.
        if (siteConfigService != null && !siteConfigService.isReady()) {
            logger.debug("MFA /cms/login gate: per-site config not ready yet (startup), failing CLOSED "
                    + "while enforcement is active");
            return true;
        }
        String siteHint = resolveSiteHint(request);
        if (siteHint != null && anyEnforcesForSite(siteHint)) {
            return true;
        }
        // The site hint said nothing (absent, or that site does not enforce): fall through to the
        // "any site enforcing?" decision over every site. This fall-through is the fix - the hint
        // can only raise the answer, never lower it.
        return isAnySiteEnforcingCached();
    }

    /** Whether the request's client IP matches the configured whitelist (the emergency door). */
    public boolean isClientWhitelisted(HttpServletRequest request) {
        String clientIp = resolveClientIp(request, trustForwardedFor.get());
        return isWhitelisted(clientIp, whitelist.get());
    }

    /**
     * The configured MFA login URL to redirect a blocked request to (per-site -> global, resolved by
     * {@link MfaLoginLogoutProvider} with the {@code redirect=} return-to-target already appended),
     * or {@code null} when none is configured or when the configured URL is {@code /cms/login}
     * itself - in which case redirecting there would loop and the caller should fall back to a 403.
     */
    public String resolveDistinctLoginUrl(HttpServletRequest request) {
        String configuredLogin = loginLogoutProvider.getLoginUrl(request);
        if (configuredLogin == null || isCmsLogin(configuredLogin, request.getContextPath())) {
            return null;
        }
        return configuredLogin;
    }

    /**
     * Whether the operator deliberately configured {@code /cms/login} itself as the (per-site or
     * global) login URL. The automatic mode uses this to tell "keep the default screen" apart from
     * "no login URL configured at all" - {@link #resolveDistinctLoginUrl} returns {@code null} for
     * both, but only the former should pass through to the password-only screen.
     */
    public boolean isCmsLoginConfigured(HttpServletRequest request) {
        String configuredLogin = loginLogoutProvider.getLoginUrl(request);
        return isCmsLogin(configuredLogin, request.getContextPath());
    }

    /**
     * Gated if any globally-enforced factor is enabled for {@code siteKey}; a throwing provider
     * fails CLOSED. Package-visible for tests.
     */
    boolean anyEnforcesForSite(String siteKey) {
        for (MfaSiteProvider provider : siteProviders) {
            try {
                if (globalPolicy.isEnforced(provider.getFactorType()) && provider.isEnabledForSite(siteKey)) {
                    return true;
                }
            } catch (RuntimeException e) {
                logger.error("MFA /cms/login gate: provider {} failed for site '{}' (failing CLOSED, request "
                        + "blocked). Cause: {}", provider.getClass().getName(), siteKey, e.getMessage());
                return true;
            }
        }
        return false;
    }

    /**
     * The site this request CLAIMS to be about: the {@code site} parameter (syntax-validated) or
     * the server-derived {@code siteKey} attribute, else {@code null}.
     * <p>
     * This is a HINT, not a trusted fact: the parameter is client-supplied on an unauthenticated
     * endpoint and {@link #SITE_KEY_PATTERN} only rules out path traversal - it does not (and
     * cannot cheaply) prove that the named site exists. {@link #isGated} therefore uses the result
     * only to gate MORE, never less.
     */
    private static String resolveSiteHint(HttpServletRequest request) {
        String param = StringUtils.trimToNull(request.getParameter(PARAM_SITE));
        if (param != null && SITE_KEY_PATTERN.matcher(param).matches()) {
            return param;
        }
        Object attr = request.getAttribute(ATTR_SITE_KEY);
        if (attr instanceof String && StringUtils.isNotBlank((String) attr)) {
            return (String) attr;
        }
        return null;
    }

    private boolean isAnySiteEnforcingCached() {
        long now = System.currentTimeMillis();
        EnforcingCache cached = enforcingCache.get();
        if (cached != null && (now - cached.timestamp) < ENFORCING_CACHE_MILLIS) {
            return cached.enforcing;
        }
        // The gate sits on an unauthenticated endpoint: cache the answer briefly so a login
        // brute-force cannot be amplified into a query flood. A fail-closed result is cached too -
        // brief over-blocking during a backend outage is the safe direction for an access gate.
        boolean enforcing = computeAnySiteEnforcing();
        enforcingCache.set(new EnforcingCache(now, enforcing));
        return enforcing;
    }

    /**
     * True if any globally-enforced factor is enabled on at least one site; a throwing provider
     * fails CLOSED. Package-visible for tests.
     */
    boolean computeAnySiteEnforcing() {
        for (MfaSiteProvider provider : siteProviders) {
            try {
                if (globalPolicy.isEnforced(provider.getFactorType()) && provider.isAnySiteEnabled()) {
                    return true;
                }
            } catch (RuntimeException e) {
                logger.error("MFA /cms/login gate: provider {} failed the global enforcement check (failing "
                        + "CLOSED, request blocked). Cause: {}", provider.getClass().getName(), e.getMessage());
                return true;
            }
        }
        return false;
    }

    /**
     * The client IP for whitelist matching. When {@code trustForwardedFor} is {@code true}, the
     * FIRST {@code X-Forwarded-For} entry is used when the header is present (the original client,
     * by convention - later entries are proxies), otherwise the socket peer address. When
     * {@code false} (the default), the header is ALWAYS ignored - but
     * {@link HttpServletRequest#getRemoteAddr()} is trusted as the socket peer ONLY when nothing
     * upstream (e.g. Tomcat's {@code RemoteIpValve}) has already rewritten it from a header; when it
     * has, {@code null} is returned so the whitelist match fails CLOSED rather than trusting a value
     * this code cannot verify (GHSA-4v3g-mcmj-83fp) - see {@link #wasAddressRewrittenFromForwardedHeader}.
     */
    static String resolveClientIp(HttpServletRequest request, boolean trustForwardedFor) {
        if (trustForwardedFor) {
            String forwarded = request.getHeader(HEADER_X_FORWARDED_FOR);
            if (StringUtils.isNotBlank(forwarded)) {
                return forwarded.split(",")[0].trim();
            }
            return request.getRemoteAddr();
        }
        if (wasAddressRewrittenFromForwardedHeader(request)) {
            return null;
        }
        return request.getRemoteAddr();
    }

    /**
     * Whether a container-level valve already rewrote {@link HttpServletRequest#getRemoteAddr()}
     * from a forwarding header before this code ran - the case Tomcat's {@code RemoteIpValve}
     * flags via {@link #ATTR_TOMCAT_REQUEST_FORWARDED} (set on the Jahia EE image by default,
     * with a permissive-by-default trusted-proxy range; GHSA-4v3g-mcmj-83fp). When this is
     * {@code true}, {@code getRemoteAddr()} is exactly as attacker-controlled as the header itself
     * would be - and, unlike some reverse-proxy integrations, the valve does not preserve the
     * pre-rewrite address anywhere this code can recover it afterwards, so there is no "true" raw
     * peer left to fall back to. Failing closed (never whitelisted) is therefore the only safe
     * response when {@code trustForwardedFor} is {@code false}.
     */
    private static boolean wasAddressRewrittenFromForwardedHeader(HttpServletRequest request) {
        return Boolean.TRUE.equals(request.getAttribute(ATTR_TOMCAT_REQUEST_FORWARDED));
    }

    /** Whether the client IP matches any whitelist entry (exact address or CIDR block). */
    static boolean isWhitelisted(String clientIp, List<String> entries) {
        if (entries.isEmpty() || !isIpLiteral(clientIp)) {
            // Never DNS-resolve the (attacker-controlled) header value: a hostname-looking
            // X-Forwarded-For must simply not match.
            return false;
        }
        byte[] client = parseAddress(clientIp);
        if (client == null) {
            return false;
        }
        for (String entry : entries) {
            if (entryMatches(client, entry)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isValidWhitelistEntry(String entry) {
        String address = entry;
        int slash = entry.indexOf('/');
        if (slash >= 0) {
            address = entry.substring(0, slash);
            String prefix = entry.substring(slash + 1);
            byte[] raw = isIpLiteral(address) ? parseAddress(address) : null;
            if (raw == null) {
                return false;
            }
            try {
                int bits = Integer.parseInt(prefix);
                return bits >= 0 && bits <= raw.length * 8;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return isIpLiteral(address) && parseAddress(address) != null;
    }

    private static boolean entryMatches(byte[] client, String entry) {
        int slash = entry.indexOf('/');
        String address = slash >= 0 ? entry.substring(0, slash) : entry;
        byte[] base = parseAddress(address);
        if (base == null || base.length != client.length) {
            return false; // mixed v4/v6 never match
        }
        int prefixBits = slash >= 0 ? Integer.parseInt(entry.substring(slash + 1)) : base.length * 8;
        return prefixMatches(client, base, prefixBits);
    }

    private static boolean prefixMatches(byte[] client, byte[] base, int prefixBits) {
        int fullBytes = prefixBits / 8;
        for (int i = 0; i < fullBytes; i++) {
            if (client[i] != base[i]) {
                return false;
            }
        }
        int remainder = prefixBits % 8;
        if (remainder == 0) {
            return true;
        }
        int mask = 0xFF << (8 - remainder);
        return (client[fullBytes] & mask) == (base[fullBytes] & mask);
    }

    /**
     * True only for strings that are syntactically IP literals - {@link InetAddress#getByName}
     * would DNS-resolve a hostname, which must never happen for attacker-controlled input.
     * IPv4 octets are range-checked too: {@code 192.168.1.256} is NOT a literal and would
     * otherwise fall through to a DNS lookup. Strings containing {@code ':'} can never be
     * hostnames (the character is illegal in DNS labels), so the IPv6 branch is safe as-is.
     */
    static boolean isIpLiteral(String value) {
        if (StringUtils.isBlank(value)) {
            return false;
        }
        if (IPV4_PATTERN.matcher(value).matches()) {
            for (String octet : value.split("\\.")) {
                if (Integer.parseInt(octet) > 255) {
                    return false;
                }
            }
            return true;
        }
        return IPV6_PATTERN.matcher(value).matches();
    }

    /** Parse an IP literal to raw bytes, or {@code null} when malformed. */
    private static byte[] parseAddress(String literal) {
        try {
            return InetAddress.getByName(literal).getAddress();
        } catch (UnknownHostException | IllegalArgumentException e) {
            return null;
        }
    }

    /** Whether the configured login URL is {@code /cms/login} itself - the operator's explicit choice. */
    static boolean isCmsLogin(String url, String contextPath) {
        if (url == null) {
            return false;
        }
        String path = StringUtils.substringBefore(url, "?");
        if (StringUtils.isNotEmpty(contextPath) && path.startsWith(contextPath)) {
            path = path.substring(contextPath.length());
        }
        return path.equals("/cms/login");
    }

    /** Immutable timestamped snapshot of the "any site enforcing?" answer. */
    private static final class EnforcingCache {
        private final long timestamp;
        private final boolean enforcing;

        private EnforcingCache(long timestamp, boolean enforcing) {
            this.timestamp = timestamp;
            this.enforcing = enforcing;
        }
    }
}
