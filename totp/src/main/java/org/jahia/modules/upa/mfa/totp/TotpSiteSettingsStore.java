package org.jahia.modules.upa.mfa.totp;

import org.jahia.modules.upa.mfa.extensions.MfaSiteConfig;
import org.jahia.modules.upa.mfa.extensions.MfaSiteConfigService;
import org.jahia.modules.upa.mfa.extensions.MfaUrls;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Reads and writes the per-site TOTP policy (enabled / enabledGroups) plus the factor-agnostic
 * per-site login/logout URLs, backed by the file OSGi <b>factory</b> configuration in
 * {@link MfaSiteConfigService} (PID {@code org.jahia.modules.mfa.extensions.site}, one {@code .cfg}
 * per site) — no longer the JCR. Enforcement (and its grace window) is GLOBAL — see the extensions
 * {@code MfaGlobalPolicy}.
 * <p>
 * Writes go through {@link MfaSiteConfigService#save}, which merges only this factor's slice (and
 * the shared URLs) so a concurrent WebAuthn write is never clobbered. Authorization is enforced in
 * the GraphQL layer ({@code MfaAdminAccess}); the URL open-redirect guard
 * ({@link MfaUrls#validateSiteRelativeUrl}) is applied here as the single chokepoint every writer
 * goes through.
 */
@Component(service = TotpSiteSettingsStore.class, immediate = true)
public class TotpSiteSettingsStore {

    private static final Logger logger = LoggerFactory.getLogger(TotpSiteSettingsStore.class);

    private MfaSiteConfigService siteConfigService;

    @Reference
    public void setSiteConfigService(MfaSiteConfigService siteConfigService) {
        this.siteConfigService = siteConfigService;
    }

    /**
     * Snapshot of the TOTP settings for a site.
     * <p>
     * The {@code urlsProvided} flag distinguishes "the caller supplied URL values to write" from
     * "the caller did not touch the URLs". The login/logout URLs are factor-agnostic and shared in
     * the same per-site {@code .cfg}: when {@code urlsProvided} is {@code false} the store performs a
     * true PARTIAL update (writes only this factor's slice and leaves any stored URLs untouched);
     * when {@code true} the URLs are written through ({@code null} clears, a path sets).
     */
    public static final class TotpSiteSettings {
        public static final TotpSiteSettings DISABLED =
                new TotpSiteSettings(false, Collections.emptyList(), null, null, false);

        private final boolean enabled;
        private final List<String> enabledGroups;
        private final String loginUrl;
        private final String logoutUrl;
        private final boolean urlsProvided;

        public TotpSiteSettings(boolean enabled, List<String> enabledGroups,
                                String loginUrl, String logoutUrl, boolean urlsProvided) {
            this.enabled = enabled;
            this.enabledGroups = enabledGroups == null
                    ? Collections.emptyList() : Collections.unmodifiableList(new ArrayList<>(enabledGroups));
            this.loginUrl = loginUrl;
            this.logoutUrl = logoutUrl;
            this.urlsProvided = urlsProvided;
        }

        public boolean isEnabled()  { return enabled; }
        public List<String> getEnabledGroups() { return enabledGroups; }

        /** Per-site custom login page URL, or {@code null} if not set (falls back to global config). */
        public String getLoginUrl()  { return loginUrl; }

        /** Per-site custom logout page URL, or {@code null} if not set (falls back to global config). */
        public String getLogoutUrl() { return logoutUrl; }

        /**
         * Whether the URLs should be written. When {@code false} the store keeps any previously
         * stored login/logout URLs (partial update); when {@code true} it writes the URL values
         * (a {@code null} clears them, a path sets them).
         */
        public boolean isUrlsProvided() { return urlsProvided; }
    }

    /**
     * Read the settings for the given site key. Returns {@link TotpSiteSettings#DISABLED} when the
     * site has no per-site config — "no config" means TOTP is OFF for that site.
     */
    public TotpSiteSettings load(String siteKey) {
        MfaSiteConfig config = siteConfigService.getConfig(siteKey);
        return new TotpSiteSettings(config.isEnabled(TotpFactorProvider.FACTOR_TYPE),
                config.enabledGroups(TotpFactorProvider.FACTOR_TYPE),
                config.getLoginUrl(), config.getLogoutUrl(), true);
    }

    /** Whether at least one site currently has TOTP enabled. */
    public boolean isAnySiteEnabled() {
        return siteConfigService.anySiteEnabled(TotpFactorProvider.FACTOR_TYPE);
    }

    /**
     * Persist the settings to the site's {@code .cfg}. The caller MUST have already validated
     * site-administrator access - this method does no permission check of its own. It DOES validate
     * the values: the URLs must be safe server-relative paths
     * ({@link MfaUrls#validateSiteRelativeUrl}).
     * <p>
     * The login/logout URLs are factor-agnostic and shared in the same per-site {@code .cfg}. URL
     * writing is therefore a true PARTIAL update driven by {@link TotpSiteSettings#isUrlsProvided()}:
     * when the flag is {@code false} the stored URLs are left untouched (only this factor's slice is
     * written); when {@code true} the URLs are written through, where a blank value (validated to
     * {@code null}) CLEARS them and a path SETS them.
     *
     * @throws IllegalArgumentException when a URL is not a safe server-relative path
     * @throws IOException              when the {@code .cfg} cannot be written
     */
    public void save(String siteKey, TotpSiteSettings settings) throws IOException {
        if (!settings.isUrlsProvided()) {
            // Partial update: write only this factor's slice, keep any previously stored URLs.
            siteConfigService.save(siteKey, current -> current
                    .withFactor(TotpFactorProvider.FACTOR_TYPE, settings.isEnabled(), settings.getEnabledGroups()));
            logger.info("TOTP site settings saved for {}: enabled={}, groups={} (URLs untouched)",
                    siteKey, settings.isEnabled(), settings.getEnabledGroups());
            return;
        }
        // validateSiteRelativeUrl("") returns null, which is the correct "clear" value here.
        String cleanLoginUrl = MfaUrls.validateSiteRelativeUrl(settings.getLoginUrl());
        String cleanLogoutUrl = MfaUrls.validateSiteRelativeUrl(settings.getLogoutUrl());
        siteConfigService.save(siteKey, current -> current
                .withFactor(TotpFactorProvider.FACTOR_TYPE, settings.isEnabled(), settings.getEnabledGroups())
                .withUrls(cleanLoginUrl, cleanLogoutUrl));
        logger.info("TOTP site settings saved for {}: enabled={}, groups={}, loginUrl={}, logoutUrl={}",
                siteKey, settings.isEnabled(), settings.getEnabledGroups(), cleanLoginUrl, cleanLogoutUrl);
    }
}
