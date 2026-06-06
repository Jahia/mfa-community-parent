package org.jahia.modules.upa.mfa.webauthn;

import org.jahia.modules.upa.mfa.extensions.MfaSiteProvider;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

import javax.jcr.RepositoryException;

/**
 * Exposes WebAuthn's per-site enrollment policy to the shared factor-agnostic infrastructure in
 * the {@code mfa-factors-extensions} bundle (the {@code /cms/login} gate), through the
 * {@link MfaSiteProvider} SPI. WebAuthn has no custom per-site login/logout pages of its own, so
 * the URL methods keep the SPI defaults ({@code null} — defer to the global config / Jahia default).
 * <p>
 * The enforcement queries feed the gate, which must fail CLOSED, so a JCR error is rethrown
 * unchecked rather than swallowed.
 */
@Component(service = MfaSiteProvider.class, immediate = true)
public class WebAuthnSiteProvider implements MfaSiteProvider {

    private WebAuthnSiteSettingsStore siteSettingsStore;

    @Reference
    public void setSiteSettingsStore(WebAuthnSiteSettingsStore siteSettingsStore) {
        this.siteSettingsStore = siteSettingsStore;
    }

    @Override
    public boolean isEnforcedForSite(String siteKey) {
        try {
            WebAuthnSiteSettingsStore.WebAuthnSiteSettings settings = siteSettingsStore.load(siteKey);
            return settings.isEnabled() && settings.isEnforced();
        } catch (RepositoryException e) {
            // The gate fails CLOSED: propagate so an unhealthy repository blocks /cms/login.
            throw new IllegalStateException("Could not read WebAuthn settings for site " + siteKey, e);
        }
    }

    @Override
    public boolean isAnySiteEnforced() {
        try {
            return siteSettingsStore.isAnySiteEnforcing();
        } catch (RepositoryException e) {
            throw new IllegalStateException("Could not evaluate WebAuthn enforcement across sites", e);
        }
    }
}
