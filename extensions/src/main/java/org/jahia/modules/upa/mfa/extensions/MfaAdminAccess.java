package org.jahia.modules.upa.mfa.extensions;

import org.jahia.modules.graphql.provider.dxm.DataFetchingException;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRSessionFactory;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.usermanager.JahiaUser;

import javax.jcr.RepositoryException;

/**
 * Shared site-administration permission gate for every factor's per-site / admin GraphQL
 * operations. The up-front {@code hasPermission} check yields a friendly, factor-specific error;
 * the JCR ACL on the write remains the load-bearing guard. Each factor passes its own error-code
 * prefix (e.g. {@code "factor.totp."}) so the surfaced error matches its message catalog.
 */
public final class MfaAdminAccess {

    public static final String SITE_ADMIN_PERMISSION = "siteAdminAccess";

    private MfaAdminAccess() {
        // utility
    }

    /**
     * Require that the current user is root or holds {@code siteAdminAccess} on the given site.
     * Returns the caller's JCR session for convenience (writes should reuse it).
     *
     * @param siteKey     the target site key
     * @param errorPrefix the factor's error-code prefix (e.g. {@code "factor.totp."}); the
     *                    surfaced codes are {@code <prefix>not_authenticated},
     *                    {@code <prefix>permission_denied} and {@code <prefix>internal_error}
     */
    public static JCRSessionWrapper requireSiteAdmin(String siteKey, String errorPrefix) {
        JahiaUser user = JCRSessionFactory.getInstance().getCurrentUser();
        if (user == null) {
            throw new DataFetchingException(errorPrefix + "not_authenticated");
        }
        try {
            JCRSessionWrapper session = JCRSessionFactory.getInstance().getCurrentUserSession();
            // nodeExists() returns false both when the site is missing and when the caller
            // cannot see it - for a non-root user the latter means "not a site admin".
            if (!session.nodeExists("/sites/" + siteKey)) {
                throw new DataFetchingException(
                        user.isRoot() ? errorPrefix + "internal_error" : errorPrefix + "permission_denied");
            }
            JCRNodeWrapper siteNode = session.getNode("/sites/" + siteKey);
            if (!user.isRoot() && !siteNode.hasPermission(SITE_ADMIN_PERMISSION)) {
                throw new DataFetchingException(errorPrefix + "permission_denied");
            }
            return session;
        } catch (RepositoryException e) {
            throw new DataFetchingException(errorPrefix + "internal_error");
        }
    }
}
