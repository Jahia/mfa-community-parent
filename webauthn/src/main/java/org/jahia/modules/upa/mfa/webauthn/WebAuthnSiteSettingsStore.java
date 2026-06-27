package org.jahia.modules.upa.mfa.webauthn;

import org.jahia.modules.upa.mfa.extensions.MfaSiteSettingsStoreBase;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.content.JCRTemplate;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.PathNotFoundException;
import javax.jcr.RepositoryException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Reads and writes the {@code upaWebauthn:siteSettings} mixin on site nodes — the per-site
 * WebAuthn policy (enabled / enabledGroups). Mirrors {@code TotpSiteSettingsStore} (without the
 * login/logout URL fields, which are TOTP-specific); the shared read/query/write helpers live in
 * {@link MfaSiteSettingsStoreBase}. Enforcement (and its grace window) is GLOBAL — see the
 * extensions {@code MfaGlobalPolicy}; the legacy per-site
 * {@code upaWebauthn:enforced}/{@code upaWebauthn:graceDays} properties remain in the CND for
 * repository compatibility but are no longer read or written.
 */
@Component(service = WebAuthnSiteSettingsStore.class, immediate = true)
public class WebAuthnSiteSettingsStore extends MfaSiteSettingsStoreBase {

    private static final Logger logger = LoggerFactory.getLogger(WebAuthnSiteSettingsStore.class);

    public static final String MIXIN_SITE_SETTINGS = "upaWebauthn:siteSettings";
    public static final String PROP_ENABLED = "upaWebauthn:enabled";
    public static final String PROP_ENABLED_GROUPS = "upaWebauthn:enabledGroups";

    @Override protected String mixinSiteSettings()  { return MIXIN_SITE_SETTINGS; }
    @Override protected String propEnabled()        { return PROP_ENABLED; }
    @Override protected String propEnabledGroups()  { return PROP_ENABLED_GROUPS; }

    /** Snapshot of the WebAuthn settings for a site. */
    public static final class WebAuthnSiteSettings {
        public static final WebAuthnSiteSettings DISABLED =
                new WebAuthnSiteSettings(false, Collections.emptyList());

        private final boolean enabled;
        private final List<String> enabledGroups;

        public WebAuthnSiteSettings(boolean enabled, List<String> enabledGroups) {
            this.enabled = enabled;
            this.enabledGroups = enabledGroups == null
                    ? Collections.emptyList() : Collections.unmodifiableList(new ArrayList<>(enabledGroups));
        }

        public boolean isEnabled()  { return enabled; }
        public List<String> getEnabledGroups() { return enabledGroups; }
    }

    public WebAuthnSiteSettings load(String siteKey) throws RepositoryException {
        if (siteKey == null || siteKey.isEmpty()) {
            return WebAuthnSiteSettings.DISABLED;
        }
        return JCRTemplate.getInstance().doExecuteWithSystemSession(systemSession -> {
            JCRNodeWrapper siteNode;
            try {
                siteNode = systemSession.getNode("/sites/" + siteKey);
            } catch (PathNotFoundException e) {
                return WebAuthnSiteSettings.DISABLED;
            }
            if (!siteNode.isNodeType(MIXIN_SITE_SETTINGS)) {
                return WebAuthnSiteSettings.DISABLED;
            }
            return new WebAuthnSiteSettings(readEnabled(siteNode), readGroups(siteNode));
        });
    }

    /**
     * Persist the settings via the caller's (admin) session. The caller MUST have validated
     * site-admin access.
     */
    public void save(JCRSessionWrapper session, String siteKey, WebAuthnSiteSettings settings)
            throws RepositoryException {
        if (siteKey == null || siteKey.isEmpty()) {
            throw new IllegalArgumentException("siteKey must not be empty");
        }
        JCRNodeWrapper siteNode = session.getNode("/sites/" + siteKey);
        List<String> cleaned = writeEnabledAndGroups(siteNode, settings.isEnabled(), settings.getEnabledGroups());
        session.save();
        logger.info("WebAuthn site settings saved for {}: enabled={}, groups={}",
                siteKey, settings.isEnabled(), cleaned);
    }
}
