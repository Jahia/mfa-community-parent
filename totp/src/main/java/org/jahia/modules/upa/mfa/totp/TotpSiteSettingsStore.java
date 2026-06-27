package org.jahia.modules.upa.mfa.totp;

import org.jahia.modules.upa.mfa.extensions.MfaSiteSettingsStoreBase;
import org.jahia.modules.upa.mfa.extensions.MfaUrls;
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
 * Reads and writes the {@code upaTotp:siteSettings} mixin on site nodes.
 * <p>
 * Per-site policy:
 * <ul>
 *   <li>{@code enabled}  — whether TOTP MFA is active on this site. When false the
 *       {@link TotpFactorProvider} short-circuits with a "skipped" marker.</li>
 *   <li>{@code enabledGroups} — if non-empty, the policy applies ONLY to members of these
 *       groups (e.g. {@code editors}); empty = all users of the site.</li>
 * </ul>
 * Enforcement (and its grace window) is GLOBAL — see the extensions {@code MfaGlobalPolicy}.
 * The legacy per-site {@code upaTotp:enforced}/{@code upaTotp:graceDays} properties remain in
 * the CND for repository compatibility but are no longer read or written.
 * <p>
 * Reads go through a system session. Writes go through the caller-provided session because
 * they are gated by a {@code siteAdmin} permission check in the GraphQL layer — the standard
 * Jahia ACL applies.
 */
@Component(service = TotpSiteSettingsStore.class, immediate = true)
public class TotpSiteSettingsStore extends MfaSiteSettingsStoreBase {

    private static final Logger logger = LoggerFactory.getLogger(TotpSiteSettingsStore.class);

    public static final String MIXIN_SITE_SETTINGS = "upaTotp:siteSettings";
    public static final String PROP_ENABLED = "upaTotp:enabled";
    public static final String PROP_ENABLED_GROUPS = "upaTotp:enabledGroups";
    public static final String PROP_LOGIN_URL = "upaTotp:loginUrl";
    public static final String PROP_LOGOUT_URL = "upaTotp:logoutUrl";

    @Override protected String mixinSiteSettings()  { return MIXIN_SITE_SETTINGS; }
    @Override protected String propEnabled()        { return PROP_ENABLED; }
    @Override protected String propEnabledGroups()  { return PROP_ENABLED_GROUPS; }

    /** Snapshot of the TOTP settings for a site. */
    public static final class TotpSiteSettings {
        public static final TotpSiteSettings DISABLED =
                new TotpSiteSettings(false, Collections.emptyList(), null, null);

        private final boolean enabled;
        private final List<String> enabledGroups;
        private final String loginUrl;
        private final String logoutUrl;

        public TotpSiteSettings(boolean enabled, List<String> enabledGroups,
                                String loginUrl, String logoutUrl) {
            this.enabled = enabled;
            this.enabledGroups = enabledGroups == null
                    ? Collections.emptyList() : Collections.unmodifiableList(new ArrayList<>(enabledGroups));
            this.loginUrl = loginUrl;
            this.logoutUrl = logoutUrl;
        }

        public boolean isEnabled()  { return enabled; }
        public List<String> getEnabledGroups() { return enabledGroups; }

        /** Per-site custom login page URL, or {@code null} if not set (falls back to global config). */
        public String getLoginUrl()  { return loginUrl; }

        /** Per-site custom logout page URL, or {@code null} if not set (falls back to global config). */
        public String getLogoutUrl() { return logoutUrl; }
    }

    /**
     * Read the settings for the given site key via a JCR system session.
     * Returns {@link TotpSiteSettings#DISABLED} if the site is missing, blank, or has
     * never had the mixin applied — "no config" means TOTP is OFF for that site.
     */
    public TotpSiteSettings load(String siteKey) throws RepositoryException {
        if (siteKey == null || siteKey.isEmpty()) {
            return TotpSiteSettings.DISABLED;
        }
        return JCRTemplate.getInstance().doExecuteWithSystemSession(systemSession -> {
            JCRNodeWrapper siteNode;
            try {
                siteNode = systemSession.getNode("/sites/" + siteKey);
            } catch (PathNotFoundException e) {
                return TotpSiteSettings.DISABLED;
            }
            if (!siteNode.isNodeType(MIXIN_SITE_SETTINGS)) {
                return TotpSiteSettings.DISABLED;
            }
            return new TotpSiteSettings(readEnabled(siteNode), readGroups(siteNode),
                    readString(siteNode, PROP_LOGIN_URL), readString(siteNode, PROP_LOGOUT_URL));
        });
    }

    /** Read a single-valued string property as a trimmed, non-empty value (or {@code null}). */
    private static String readString(JCRNodeWrapper siteNode, String property) throws RepositoryException {
        if (!siteNode.hasProperty(property)) {
            return null;
        }
        String value = siteNode.getProperty(property).getString();
        return (value == null || value.trim().isEmpty()) ? null : value.trim();
    }

    /**
     * Persist the settings via the caller's session (i.e. the authenticated admin's session).
     * The caller MUST have already validated site-administrator access — this method does no
     * permission check of its own. It DOES validate the values: the URLs must be safe
     * server-relative paths (see {@link MfaUrls#validateSiteRelativeUrl}) — this is the single
     * chokepoint every writer goes through, so the open-redirect guard cannot be bypassed by a
     * future caller.
     *
     * @throws IllegalArgumentException when a URL is not a safe server-relative path
     */
    public void save(JCRSessionWrapper session, String siteKey, TotpSiteSettings settings)
            throws RepositoryException {
        if (siteKey == null || siteKey.isEmpty()) {
            throw new IllegalArgumentException("siteKey must not be empty");
        }
        String cleanLoginUrl = MfaUrls.validateSiteRelativeUrl(settings.getLoginUrl());
        String cleanLogoutUrl = MfaUrls.validateSiteRelativeUrl(settings.getLogoutUrl());
        JCRNodeWrapper siteNode = session.getNode("/sites/" + siteKey);
        List<String> cleaned = writeEnabledAndGroups(siteNode, settings.isEnabled(), settings.getEnabledGroups());
        setOrRemove(siteNode, PROP_LOGIN_URL, cleanLoginUrl);
        setOrRemove(siteNode, PROP_LOGOUT_URL, cleanLogoutUrl);
        session.save();
        logger.info("TOTP site settings saved for {}: enabled={}, groups={}, loginUrl={}, logoutUrl={}",
                siteKey, settings.isEnabled(), cleaned, cleanLoginUrl, cleanLogoutUrl);
    }

    /** Set a single-valued string property to its trimmed value, or remove it when blank. */
    private static void setOrRemove(JCRNodeWrapper siteNode, String property, String value) throws RepositoryException {
        String trimmed = (value == null) ? null : value.trim();
        if (trimmed == null || trimmed.isEmpty()) {
            if (siteNode.hasProperty(property)) {
                siteNode.getProperty(property).remove();
            }
        } else {
            siteNode.setProperty(property, trimmed);
        }
    }
}
