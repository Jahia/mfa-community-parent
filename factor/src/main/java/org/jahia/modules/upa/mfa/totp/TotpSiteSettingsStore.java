package org.jahia.modules.upa.mfa.totp;

import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.content.JCRTemplate;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.PathNotFoundException;
import javax.jcr.RepositoryException;

/**
 * Reads and writes the {@code upaTotp:siteSettings} mixin on site nodes.
 * <p>
 * Two settings are stored per site:
 * <ul>
 *   <li>{@code enabled}  — whether TOTP MFA is active on this site. When false, the
 *       {@link TotpFactorProvider} short-circuits its preparation/verification with a
 *       "skipped" marker so logins for this site proceed without a TOTP challenge.</li>
 *   <li>{@code enforced} — whether enrollment is mandatory. When true and the user has
 *       not enrolled, {@code prepare()} raises {@code factor.totp.enrollment_required}
 *       so the login UI can redirect the user to the enrollment page.</li>
 * </ul>
 * <p>
 * Reads go through a system session (anyone in the MFA flow can need them). Writes go
 * through the caller-provided session because writes are gated by a {@code siteAdmin}
 * permission check in the GraphQL layer — the standard Jahia ACL applies.
 */
@Component(service = TotpSiteSettingsStore.class, immediate = true)
public class TotpSiteSettingsStore {

    private static final Logger logger = LoggerFactory.getLogger(TotpSiteSettingsStore.class);

    public static final String MIXIN_SITE_SETTINGS = "upaTotp:siteSettings";
    public static final String PROP_ENABLED = "upaTotp:enabled";
    public static final String PROP_ENFORCED = "upaTotp:enforced";

    /** Snapshot of the TOTP settings for a site. Both default to false. */
    public static final class TotpSiteSettings {
        public static final TotpSiteSettings DISABLED = new TotpSiteSettings(false, false);

        private final boolean enabled;
        private final boolean enforced;

        public TotpSiteSettings(boolean enabled, boolean enforced) {
            this.enabled = enabled;
            this.enforced = enforced;
        }

        public boolean isEnabled()  { return enabled; }
        public boolean isEnforced() { return enforced; }
    }

    /**
     * Read the settings for the given site key via a JCR system session.
     * Returns {@link TotpSiteSettings#DISABLED} if the site is missing, blank, or has
     * never had the mixin applied — defensively, "no config" means TOTP is OFF for
     * that site so the factor never surprises an admin who hasn't opted in.
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
            boolean enabled = siteNode.hasProperty(PROP_ENABLED)
                    && siteNode.getProperty(PROP_ENABLED).getBoolean();
            boolean enforced = siteNode.hasProperty(PROP_ENFORCED)
                    && siteNode.getProperty(PROP_ENFORCED).getBoolean();
            return new TotpSiteSettings(enabled, enforced);
        });
    }

    /**
     * Persist the settings via the caller's session (i.e. the authenticated admin's
     * JCR session). The caller MUST have already validated that the user is a site
     * administrator — this method does no permission check of its own.
     */
    public void save(JCRSessionWrapper session, String siteKey,
                     boolean enabled, boolean enforced) throws RepositoryException {
        if (siteKey == null || siteKey.isEmpty()) {
            throw new IllegalArgumentException("siteKey must not be empty");
        }
        JCRNodeWrapper siteNode = session.getNode("/sites/" + siteKey);
        if (!siteNode.isNodeType(MIXIN_SITE_SETTINGS)) {
            siteNode.addMixin(MIXIN_SITE_SETTINGS);
        }
        siteNode.setProperty(PROP_ENABLED, enabled);
        siteNode.setProperty(PROP_ENFORCED, enforced);
        session.save();
        logger.info("TOTP site settings saved for {}: enabled={}, enforced={}",
                siteKey, enabled, enforced);
    }
}
