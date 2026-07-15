package org.jahia.modules.upa.mfa.extensions.internal;

import org.jahia.modules.upa.mfa.extensions.MfaGlobalPolicy;
import org.jahia.modules.upa.mfa.extensions.MfaSiteConfigService;
import org.jahia.modules.upa.mfa.extensions.MfaSiteProvider;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Hashtable;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * REGRESSION guard for U8 — the (formerly &le;60&nbsp;s) fail-OPEN window in the no-site branch of
 * the {@code /cms/login} gate is CLOSED.
 * <p>
 * {@link MfaLoginGateDecision#isAnySiteEnforcingCached()} caches the "is any site enforcing?" answer
 * for {@code ENFORCING_CACHE_MILLIS = 60_000} so the unauthenticated gate stays cheap. Before the
 * fix, that cache was invalidated only on provider bind/unbind and the decision's own
 * {@code @Activate}/{@code @Modified} — never when {@link MfaSiteConfigService#updated} enabled a
 * factor on the FIRST enforcing site. A no-site {@code /cms/login} POST that had cached
 * {@code enforcing=false} therefore kept authenticating password-only for up to a minute: a
 * fail-OPEN in a security gate.
 * <p>
 * The fix makes {@link MfaSiteConfigService} a source of
 * {@link org.jahia.modules.upa.mfa.extensions.MfaSiteConfigChangeListener} notifications on every
 * config change ({@code updated()}/{@code deleted()}/{@code save()}), and
 * {@link MfaLoginGateDecision} implements that listener to drop its enforcing cache. The reverse edge
 * (config service → decision) is an <b>optional/dynamic</b> OSGi reference, so it cannot form an
 * activation cycle with the decision's existing mandatory reference to the config service (for
 * {@link MfaSiteConfigService#isReady()}). This test wires that listener relationship the same way
 * DS would ({@link MfaSiteConfigService#bindChangeListener}) and asserts the window is now closed.
 */
public class MfaLoginGateEnforcingCacheInvalidationTest {

    private static final String FACTOR = "totp";

    /**
     * The former &le;60&nbsp;s fail-open is closed: after a no-site gate has cached "not enforcing",
     * enabling totp on the FIRST site via a FileInstall {@code updated()} replay now invalidates the
     * decision's enforcing cache through the change-listener callback, so the very next no-site
     * {@code /cms/login} request — well inside the old 60&nbsp;s window — is gated.
     */
    @Test
    public void firstSiteEnableClosesTheNoSiteWindowImmediately() throws Exception {
        MfaSiteConfigService configService = activatedEmptyConfigService();
        MfaLoginGateDecision decision = noSiteDecision(configService);
        HttpServletRequest noSiteLogin = loginRequest();

        // (1) Prime the no-site cache while no site enforces → caches enforcing=false for 60 s.
        assertFalse("no site enforces yet → not gated", decision.isGated(noSiteLogin));

        // (2) An admin enables totp on the FIRST site (FileInstall delivers the new .cfg). This fires
        //     the change-listener callback that invalidates the decision's stale cache.
        configService.updated("org.jahia.modules.mfa.extensions.site-siteA", totpEnabledCfg("siteA"));
        assertTrue("the config service now reports totp enabled on a site",
                configService.anySiteEnabled(FACTOR));

        // (3) Re-check the no-site gate immediately, well inside the old 60 s window.
        boolean gatedWithinWindow = decision.isGated(noSiteLogin);

        // REGRESSION: the fail-open is closed — enabling the first enforcing site invalidates the
        // no-site gate's cache at once, so no password-only window remains (was assertFalse before U8).
        assertTrue("U8 REGRESSION: enabling the first enforcing site must close the no-site gate's "
                + "cache window immediately (no <=60s fail-open)", gatedWithinWindow);
    }

    /**
     * Removing the last enforcing site's config also invalidates the cache promptly, so the gate does
     * not keep blocking (over-enforcing) off a stale "enforcing" answer — the invalidation is
     * symmetric with enable.
     */
    @Test
    public void lastSiteDisableClearsTheCachePromptly() throws Exception {
        MfaSiteConfigService configService = activatedEmptyConfigService();
        MfaLoginGateDecision decision = noSiteDecision(configService);
        HttpServletRequest noSiteLogin = loginRequest();

        configService.updated("org.jahia.modules.mfa.extensions.site-siteA", totpEnabledCfg("siteA"));
        assertTrue("gated once a site enforces", decision.isGated(noSiteLogin));

        configService.deleted("org.jahia.modules.mfa.extensions.site-siteA");
        assertFalse("no site enforces after the config is removed → not gated (cache was invalidated)",
                decision.isGated(noSiteLogin));
    }

    /**
     * Control: the site-context branch ({@link MfaLoginGateDecision#anyEnforcesForSite}) is
     * <b>uncached</b>, so a request that carries the {@code site} context sees the first-site enable
     * immediately regardless of the listener — this bounds the scope of the cache to the no-site branch.
     */
    @Test
    public void siteContextBranchIsUncachedAndUnaffected() throws Exception {
        MfaSiteConfigService configService = activatedEmptyConfigService();
        MfaLoginGateDecision decision = noSiteDecision(configService);
        HttpServletRequest siteALogin = loginRequestForSite("siteA");

        assertFalse("siteA does not enforce yet", decision.isGated(siteALogin));

        configService.updated("org.jahia.modules.mfa.extensions.site-siteA", totpEnabledCfg("siteA"));

        assertTrue("the site-context branch is uncached → gated immediately",
                decision.isGated(siteALogin));
    }

    // --- helpers --------------------------------------------------------------------------------

    /**
     * A decision enforcing totp globally, backed by a provider that reads live from the config
     * service, AND registered as a config-change listener on that service the way DS wires the
     * optional/dynamic reverse reference at runtime.
     */
    private static MfaLoginGateDecision noSiteDecision(MfaSiteConfigService configService) {
        MfaLoginGateDecision decision = new MfaLoginGateDecision();
        MfaGlobalPolicy policy = new MfaGlobalPolicy();
        Hashtable<String, Object> policyProps = new Hashtable<>();
        policyProps.put("enforcedFactors", FACTOR);
        policy.activate(policyProps);
        decision.setGlobalPolicy(policy);
        decision.setLoginLogoutProvider(new MfaLoginLogoutProvider());
        decision.setSiteConfigService(configService);
        decision.bindSiteProvider(providerBackedBy(configService));
        configService.bindChangeListener(decision); // the optional/dynamic reverse wire DS performs
        return decision;
    }

    /** A site provider whose per-site and any-site answers read live from the config service. */
    private static MfaSiteProvider providerBackedBy(MfaSiteConfigService configService) {
        return new MfaSiteProvider() {
            @Override
            public String getFactorType() {
                return FACTOR;
            }

            @Override
            public boolean isEnabledForSite(String siteKey) {
                return configService.getConfig(siteKey).isEnabled(FACTOR);
            }

            @Override
            public boolean isAnySiteEnabled() {
                return configService.anySiteEnabled(FACTOR);
            }

            @Override
            public boolean isConfiguredForUser(String userId) {
                return false;
            }
        };
    }

    private static Hashtable<String, Object> totpEnabledCfg(String siteKey) {
        Hashtable<String, Object> cfg = new Hashtable<>();
        cfg.put("siteKey", siteKey);
        cfg.put(FACTOR + ".enabled", "true");
        return cfg;
    }

    /** A {@link MfaSiteConfigService} activated over an empty etc dir: ready, no sites configured. */
    private static MfaSiteConfigService activatedEmptyConfigService() throws Exception {
        Path emptyEtc = Files.createTempDirectory("mfa-u8-etc");
        emptyEtc.toFile().deleteOnExit();
        String previous = System.getProperty("karaf.etc");
        System.setProperty("karaf.etc", emptyEtc.toAbsolutePath().toString());
        try {
            MfaSiteConfigService service = new MfaSiteConfigService();
            service.activate();
            return service;
        } finally {
            if (previous == null) {
                System.clearProperty("karaf.etc");
            } else {
                System.setProperty("karaf.etc", previous);
            }
        }
    }

    private static HttpServletRequest loginRequest() {
        return loginRequestForSite(null);
    }

    private static HttpServletRequest loginRequestForSite(String siteKey) {
        return (HttpServletRequest) Proxy.newProxyInstance(
                MfaLoginGateEnforcingCacheInvalidationTest.class.getClassLoader(),
                new Class<?>[]{HttpServletRequest.class},
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "getRequestURI":
                            return "/cms/login";
                        case "getContextPath":
                            return "";
                        case "getRemoteAddr":
                            return "198.51.100.23";
                        case "getParameter":
                            return "site".equals(args[0]) ? siteKey : null;
                        default:
                            return null;
                    }
                });
    }
}
