package org.jahia.modules.upa.mfa.extensions.internal;

import org.jahia.modules.upa.mfa.extensions.MfaGlobalPolicy;
import org.jahia.modules.upa.mfa.extensions.MfaSiteConfigService;
import org.jahia.modules.upa.mfa.extensions.MfaSiteProvider;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Hashtable;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * CHARACTERIZATION test for U8 — the bounded (&le;60&nbsp;s) fail-OPEN window in the no-site branch
 * of the {@code /cms/login} gate.
 * <p>
 * <b>Stage-7 handoff:</b> this test documents the CURRENT behaviour so the fix is verifiable, and
 * it must NOT be "fixed" here. {@link MfaLoginGateDecision#isAnySiteEnforcingCached()} caches the
 * "is any site enforcing?" answer for {@code ENFORCING_CACHE_MILLIS = 60_000}. The cache is
 * invalidated only on provider bind/unbind and the decision's own {@code @Activate}/{@code @Modified}
 * (see {@link MfaLoginGateDecision#bindSiteProvider}, {@link MfaLoginGateDecision#unbindSiteProvider}
 * and {@link MfaLoginGateDecision#activate}) — <b>never</b> when {@link MfaSiteConfigService#updated}
 * toggles a factor on for the first enforcing site. So a no-site {@code /cms/login} POST that cached
 * {@code enforcing=false} keeps authenticating password-only for up to 60&nbsp;s after totp is
 * enabled on the first site.
 * <p>
 * The Stage-7 fix wires {@code MfaSiteConfigService.updated()/deleted()/save()} to invalidate the
 * decision's enforcing cache (via an optional/dynamic reverse reference or event callback — a
 * <b>mandatory</b> reverse {@code @Reference} would create an OSGi activation cycle, since the
 * decision already {@code @Reference}s the config service for {@link MfaSiteConfigService#isReady()}).
 * When that ships, the {@code assertFalse} on {@code gatedWithinWindow} below flips to
 * {@code assertTrue} and this class can be renamed to a regression guard.
 */
public class MfaLoginGateFailOpenWindowTest {

    private static final String FACTOR = "totp";

    /**
     * The documented &le;60&nbsp;s fail-open: after a no-site gate has cached "not enforcing",
     * enabling totp on the FIRST site via a FileInstall {@code updated()} replay does NOT close the
     * window — the no-site gate still reports "not gated". Invalidating the cache (what the Stage-7
     * fix wires {@code updated()} to do) closes it immediately, proving the cache is the sole cause.
     */
    @Test
    public void characterization_firstSiteEnableDoesNotCloseTheNoSiteWindow() throws Exception {
        MfaSiteConfigService configService = activatedEmptyConfigService();
        MfaLoginGateDecision decision = noSiteDecision(configService);
        HttpServletRequest noSiteLogin = loginRequest();

        // (1) Prime the no-site cache while no site enforces → caches enforcing=false for 60 s.
        assertFalse("no site enforces yet → not gated", decision.isGated(noSiteLogin));

        // (2) An admin enables totp on the FIRST site (FileInstall delivers the new .cfg).
        configService.updated("org.jahia.modules.mfa.extensions.site-siteA", totpEnabledCfg("siteA"));
        assertTrue("the config service now reports totp enabled on a site",
                configService.anySiteEnabled(FACTOR));

        // (3) Re-check the no-site gate immediately, well inside the 60 s window.
        boolean gatedWithinWindow = decision.isGated(noSiteLogin);

        // CHARACTERIZATION of the CURRENT fail-open (Stage-7 flips this to assertTrue after the fix):
        // updated() never poked the decision's enforcingCache, so the stale "false" still wins.
        assertFalse("DOCUMENTED FAIL-OPEN (U8): enabling the first enforcing site does not close the "
                + "no-site gate's <=60s cache window", gatedWithinWindow);

        // Prove the cache is the sole cause: invalidating it (the fix's effect) closes the window now.
        invalidateEnforcingCache(decision);
        assertTrue("once the enforcing cache is invalidated the no-site gate closes immediately",
                decision.isGated(noSiteLogin));
    }

    /**
     * Control: the site-context branch ({@link MfaLoginGateDecision#anyEnforcesForSite}) is
     * <b>uncached</b>, so a request that carries the {@code site} context sees the first-site enable
     * immediately — no fail-open window there. This bounds the scope of U8 to the no-site branch.
     */
    @Test
    public void siteContextBranchIsUncachedAndUnaffected() throws Exception {
        MfaSiteConfigService configService = activatedEmptyConfigService();
        MfaLoginGateDecision decision = noSiteDecision(configService);
        HttpServletRequest siteALogin = loginRequestForSite("siteA");

        assertFalse("siteA does not enforce yet", decision.isGated(siteALogin));

        configService.updated("org.jahia.modules.mfa.extensions.site-siteA", totpEnabledCfg("siteA"));

        assertTrue("the site-context branch is uncached → gated immediately, no fail-open window",
                decision.isGated(siteALogin));
    }

    // --- helpers --------------------------------------------------------------------------------

    /** A decision enforcing totp globally, backed by a provider that reads live from the config service. */
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

    /** Reflectively null the decision's enforcing cache — the effect the Stage-7 fix will wire. */
    @SuppressWarnings("unchecked")
    private static void invalidateEnforcingCache(MfaLoginGateDecision decision) throws Exception {
        Field f = MfaLoginGateDecision.class.getDeclaredField("enforcingCache");
        f.setAccessible(true);
        ((AtomicReference<Object>) f.get(decision)).set(null);
    }

    private static HttpServletRequest loginRequest() {
        return loginRequestForSite(null);
    }

    private static HttpServletRequest loginRequestForSite(String siteKey) {
        return (HttpServletRequest) Proxy.newProxyInstance(
                MfaLoginGateFailOpenWindowTest.class.getClassLoader(),
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
