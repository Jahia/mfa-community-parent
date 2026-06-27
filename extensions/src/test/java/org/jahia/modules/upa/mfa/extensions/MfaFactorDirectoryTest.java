package org.jahia.modules.upa.mfa.extensions;

import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * {@link MfaFactorDirectory#configuredFactorsForUser}: the list driving the login UI's factor
 * chooser — only factors the user configured AND may use on the site, in provider registration
 * order, deduplicated.
 */
public class MfaFactorDirectoryTest {

    private static final String USER = "alice";
    private static final String SITE = "siteA";

    private MfaFactorDirectory directory;
    private MfaGlobalPolicy policy;

    @Before
    public void setUp() {
        directory = new MfaFactorDirectory();
        policy = new MfaGlobalPolicy();
        policy.activate(java.util.Collections.emptyMap());
        directory.setGlobalPolicy(policy);
    }

    private void enforce(String enforcedFactors) {
        Map<String, Object> props = new HashMap<>();
        props.put("enforcedFactors", enforcedFactors);
        policy.activate(props);
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

    private static MfaSiteProvider provider(String type, boolean configured, boolean enabledOnSite) {
        return new MfaSiteProvider() {
            @Override
            public String getFactorType() {
                return type;
            }

            @Override
            public boolean isEnabledForSite(String siteKey) {
                return enabledOnSite;
            }

            @Override
            public boolean isAnySiteEnabled() {
                return enabledOnSite;
            }

            @Override
            public boolean isConfiguredForUser(String userId) {
                return configured;
            }
        };
    }

    @Test
    public void onlyConfiguredFactorsAreListed() {
        directory.bindSiteProvider(provider("totp", false, true));
        directory.bindSiteProvider(provider("webauthn", true, true));
        assertEquals(Arrays.asList("webauthn"), directory.configuredFactorsForUser(USER, SITE));
    }

    @Test
    public void factorDisabledOnTheSiteIsExcluded() {
        // Configured but disabled on this site: it would skip at prepare anyway — offering it
        // in the chooser would recreate the picked-totp-landed-on-webauthn confusion.
        directory.bindSiteProvider(provider("totp", true, false));
        directory.bindSiteProvider(provider("webauthn", true, true));
        assertEquals(Arrays.asList("webauthn"), directory.configuredFactorsForUser(USER, SITE));
    }

    @Test
    public void withoutSiteContextTheSiteCheckIsSkipped() {
        directory.bindSiteProvider(provider("totp", true, false));
        assertEquals(Arrays.asList("totp"), directory.configuredFactorsForUser(USER, null));
        assertEquals(Arrays.asList("totp"), directory.configuredFactorsForUser(USER, "  "));
    }

    @Test
    public void nothingConfiguredYieldsEmptyList() {
        directory.bindSiteProvider(provider("totp", false, true));
        directory.bindSiteProvider(provider("webauthn", false, true));
        assertTrue(directory.configuredFactorsForUser(USER, SITE).isEmpty());
    }

    @Test
    public void duplicateProviderTypesAreListedOnce() {
        directory.bindSiteProvider(provider("totp", true, true));
        directory.bindSiteProvider(provider("totp", true, true));
        List<String> result = directory.configuredFactorsForUser(USER, SITE);
        assertEquals(Arrays.asList("totp"), result);
    }

    // --- hasAnyEnforcedFactorConfigured (the pre-auth anti-takeover barrier) ----------------

    @Test
    public void hasAnyEnforced_enforcedAndConfigured_isTrue() {
        enforce("totp");
        directory.bindSiteProvider(provider("totp", true, true));
        assertTrue(directory.hasAnyEnforcedFactorConfigured(USER));
    }

    @Test
    public void hasAnyEnforced_configuredButNotEnforced_isFalse() {
        enforce("webauthn"); // totp is configured but NOT in the enforced set
        directory.bindSiteProvider(provider("totp", true, true));
        assertFalse(directory.hasAnyEnforcedFactorConfigured(USER));
    }

    @Test
    public void hasAnyEnforced_enforcedButNotConfigured_isFalse() {
        enforce("totp");
        directory.bindSiteProvider(provider("totp", false, true));
        assertFalse(directory.hasAnyEnforcedFactorConfigured(USER));
    }

    @Test
    public void hasAnyEnforced_nothingConfigured_isFalse() {
        enforce("totp,webauthn");
        directory.bindSiteProvider(provider("totp", false, true));
        directory.bindSiteProvider(provider("webauthn", false, true));
        assertFalse(directory.hasAnyEnforcedFactorConfigured(USER));
    }

    @Test
    public void hasAnyEnforced_providerThrows_propagatesFailClosed() {
        // The anti-takeover barrier must fail CLOSED: a provider that cannot answer propagates its
        // unchecked exception so the caller refuses pre-auth enrollment rather than assuming "no".
        enforce("totp");
        directory.bindSiteProvider(throwingProvider("totp"));
        try {
            directory.hasAnyEnforcedFactorConfigured(USER);
            fail("expected the provider's unchecked exception to propagate (fail closed)");
        } catch (IllegalStateException e) {
            assertEquals("repository unavailable", e.getMessage());
        }
    }
}
