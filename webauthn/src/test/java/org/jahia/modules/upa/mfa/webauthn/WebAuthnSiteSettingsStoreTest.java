package org.jahia.modules.upa.mfa.webauthn;

import org.jahia.modules.upa.mfa.extensions.MfaSiteConfig;
import org.jahia.modules.upa.mfa.extensions.MfaSiteConfigService;
import org.jahia.modules.upa.mfa.webauthn.WebAuthnSiteSettingsStore.WebAuthnSiteSettings;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for {@link WebAuthnSiteSettingsStore}, backed by a real {@link MfaSiteConfigService}
 * over a {@link TemporaryFolder} ({@code karaf.etc}). The high-stakes invariant: a WebAuthn save
 * owns ONLY its enabled/enabledGroups slice and must NOT touch the factor-agnostic per-site
 * login/logout URLs that share the same single {@code .cfg} (those are owned via the TOTP path).
 */
public class WebAuthnSiteSettingsStoreTest {

    private static final String FACTOR_TOTP = "totp";
    private static final String SITE_KEY = "digitall";

    @Rule
    public TemporaryFolder etc = new TemporaryFolder();

    private MfaSiteConfigService service;
    private WebAuthnSiteSettingsStore store;

    @Before
    public void setUp() {
        System.setProperty("karaf.etc", etc.getRoot().getAbsolutePath());
        service = new MfaSiteConfigService();
        store = new WebAuthnSiteSettingsStore();
        store.setSiteConfigService(service);
    }

    @After
    public void tearDown() {
        System.clearProperty("karaf.etc");
    }

    @Test
    public void saveKeepsTheSharedLoginUrlAndTheTotpSlice() throws Exception {
        // Prime the shared per-site config: TOTP enabled AND a loginUrl set (owned via TOTP path).
        service.save(SITE_KEY, current ->
                current.withFactor(FACTOR_TOTP, true, Arrays.asList("editors")).withUrls("/login.html", null));

        // WebAuthn save merges ONLY its own slice.
        List<String> groups = Arrays.asList("reviewers");
        store.save(SITE_KEY, new WebAuthnSiteSettings(true, groups));

        MfaSiteConfig config = service.getConfig(SITE_KEY);
        // The shared loginUrl survived the WebAuthn write.
        assertEquals("/login.html", config.getLoginUrl());
        // The WebAuthn slice is now enabled with its groups.
        assertTrue(config.isEnabled(WebAuthnFactorProvider.FACTOR_TYPE));
        assertEquals(groups, config.enabledGroups(WebAuthnFactorProvider.FACTOR_TYPE));
        // The TOTP slice is untouched.
        assertTrue(config.isEnabled(FACTOR_TOTP));
        assertEquals(Arrays.asList("editors"), config.enabledGroups(FACTOR_TOTP));

        // And the store reads its slice back the same way.
        WebAuthnSiteSettings loaded = store.load(SITE_KEY);
        assertTrue(loaded.isEnabled());
        assertEquals(groups, loaded.getEnabledGroups());
    }

    @Test
    public void loadWhenAbsentReturnsDisabled() {
        WebAuthnSiteSettings loaded = store.load("no-such-site");
        assertFalse(loaded.isEnabled());
        assertEquals(Collections.emptyList(), loaded.getEnabledGroups());
    }
}
