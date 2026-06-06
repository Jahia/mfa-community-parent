package org.jahia.modules.upa.mfa.totp;

import org.jahia.modules.upa.mfa.extensions.MfaSiteProvider;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

import javax.jcr.RepositoryException;

/**
 * Exposes TOTP's per-site enrollment policy and custom login/logout URLs to the shared
 * factor-agnostic infrastructure in the {@code mfa-factors-extensions} bundle (the
 * {@code /cms/login} gate and the login/logout URL provider), through the {@link MfaSiteProvider}
 * SPI. This is the only seam between TOTP and that bundle for these concerns — it keeps the shared
 * code free of any compile-time dependency on {@link TotpSiteSettingsStore}.
 * <p>
 * Enforcement queries ({@link #isEnforcedForSite}/{@link #isAnySiteEnforced}) feed the gate, which
 * must fail CLOSED, so a JCR error is rethrown unchecked rather than swallowed. URL queries feed
 * the URL provider, which falls back to Jahia's default when no safe URL is available, so a JCR
 * error there simply yields {@code null} ("no custom URL").
 */
@Component(service = MfaSiteProvider.class, immediate = true)
public class TotpSiteProvider implements MfaSiteProvider {

    private TotpSiteSettingsStore siteSettingsStore;

    @Reference
    public void setSiteSettingsStore(TotpSiteSettingsStore siteSettingsStore) {
        this.siteSettingsStore = siteSettingsStore;
    }

    @Override
    public boolean isEnforcedForSite(String siteKey) {
        try {
            TotpSiteSettingsStore.TotpSiteSettings settings = siteSettingsStore.load(siteKey);
            return settings.isEnabled() && settings.isEnforced();
        } catch (RepositoryException e) {
            // The gate fails CLOSED: propagate so an unhealthy repository blocks /cms/login.
            throw new IllegalStateException("Could not read TOTP settings for site " + siteKey, e);
        }
    }

    @Override
    public boolean isAnySiteEnforced() {
        try {
            return siteSettingsStore.isAnySiteEnforcing();
        } catch (RepositoryException e) {
            throw new IllegalStateException("Could not evaluate TOTP enforcement across sites", e);
        }
    }

    @Override
    public String getLoginUrl(String siteKey) {
        return perSiteUrl(siteKey, true);
    }

    @Override
    public String getLogoutUrl(String siteKey) {
        return perSiteUrl(siteKey, false);
    }

    /** The per-site login/logout URL stored for TOTP, or {@code null} (incl. on a JCR error). */
    private String perSiteUrl(String siteKey, boolean login) {
        try {
            TotpSiteSettingsStore.TotpSiteSettings settings = siteSettingsStore.load(siteKey);
            return login ? settings.getLoginUrl() : settings.getLogoutUrl();
        } catch (RepositoryException e) {
            // URL provider falls back to Jahia default; a read error is just "no custom URL".
            return null;
        }
    }
}
