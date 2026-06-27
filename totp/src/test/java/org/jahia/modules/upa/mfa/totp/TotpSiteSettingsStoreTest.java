package org.jahia.modules.upa.mfa.totp;

import org.jahia.modules.upa.mfa.extensions.MfaSiteConfigService;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for {@link TotpSiteSettingsStore}, backed by a real {@link MfaSiteConfigService} over a
 * {@link TemporaryFolder} used as {@code karaf.etc} (no running container). Mirrors the JUnit4 style
 * of {@code MfaSiteConfigServiceTest}.
 * <p>
 * The login/logout URLs are factor-agnostic and shared in the same per-site {@code .cfg}, so a TOTP
 * write that does NOT carry URLs ({@code urlsProvided == false}) must be a true PARTIAL update that
 * preserves any previously stored URLs - this is the data-loss fix under test.
 */
public class TotpSiteSettingsStoreTest {

    private static final String SITE_KEY = "digitall";

    @Rule
    public TemporaryFolder etc = new TemporaryFolder();

    private TotpSiteSettingsStore store;

    @Before
    public void setUp() {
        System.setProperty("karaf.etc", etc.getRoot().getAbsolutePath());
        store = new TotpSiteSettingsStore();
        store.setSiteConfigService(new MfaSiteConfigService());
    }

    @After
    public void tearDown() {
        System.clearProperty("karaf.etc");
    }

    private static TotpSiteSettingsStore.TotpSiteSettings withUrls(boolean enabled, String loginUrl, String logoutUrl) {
        return new TotpSiteSettingsStore.TotpSiteSettings(enabled, Collections.emptyList(), loginUrl, logoutUrl, true);
    }

    private static TotpSiteSettingsStore.TotpSiteSettings urlsOmitted(boolean enabled) {
        return new TotpSiteSettingsStore.TotpSiteSettings(enabled, Collections.emptyList(), null, null, false);
    }

    @Test
    public void omittedUrlsPreservePreviouslyStoredLoginUrl() throws Exception {
        // Arrange: a first save sets a login URL (URLs provided).
        store.save(SITE_KEY, withUrls(true, "/login.html", null));
        assertEquals("/login.html", store.load(SITE_KEY).getLoginUrl());

        // Act: a second save toggles enabled and OMITS the URLs (partial update).
        store.save(SITE_KEY, urlsOmitted(false));

        // Assert: the previously stored login URL survives, only the factor slice changed.
        TotpSiteSettingsStore.TotpSiteSettings reloaded = store.load(SITE_KEY);
        assertEquals("loginUrl must survive an URL-omitting save", "/login.html", reloaded.getLoginUrl());
        assertFalse("enabled toggle must apply", reloaded.isEnabled());
    }

    @Test
    public void emptyStringLoginUrlClearsTheStoredValue() throws Exception {
        // Arrange: a stored login URL.
        store.save(SITE_KEY, withUrls(true, "/login.html", null));
        assertEquals("/login.html", store.load(SITE_KEY).getLoginUrl());

        // Act: an explicit clear - empty string is provided (urlsProvided == true), validated to null.
        store.save(SITE_KEY, withUrls(true, "", null));

        // Assert: the URL is cleared.
        assertNull("empty-string loginUrl must clear the stored value", store.load(SITE_KEY).getLoginUrl());
    }

    @Test
    public void invalidUrlIsRejected() {
        // The open-redirect guard rejects a non server-relative path.
        final TotpSiteSettingsStore.TotpSiteSettings settings = withUrls(true, "http://evil", null);
        assertThrows(IllegalArgumentException.class, () -> store.save(SITE_KEY, settings));
    }

    @Test
    public void loadWhenAbsentReturnsDisabledEmpty() {
        TotpSiteSettingsStore.TotpSiteSettings settings = store.load("never-configured");
        assertFalse("absent site must be disabled", settings.isEnabled());
        assertTrue("absent site must have no enabled groups", settings.getEnabledGroups().isEmpty());
        assertNull("absent site must have no login URL", settings.getLoginUrl());
        assertNull("absent site must have no logout URL", settings.getLogoutUrl());
    }
}
