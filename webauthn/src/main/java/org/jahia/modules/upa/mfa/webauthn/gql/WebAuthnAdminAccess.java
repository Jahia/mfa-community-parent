package org.jahia.modules.upa.mfa.webauthn.gql;

import org.jahia.modules.graphql.provider.dxm.DataFetchingException;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRSessionFactory;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.usermanager.JahiaUser;

import javax.jcr.RepositoryException;

/**
 * Shared site-administration permission gate for the per-site / admin WebAuthn GraphQL
 * operations. Mirrors {@code TotpAdminAccess}: an up-front {@code hasPermission} check for a
 * friendly error, with the JCR ACL on the write as the load-bearing guard.
 */
final class WebAuthnAdminAccess {

    static final String SITE_ADMIN_PERMISSION = "siteAdminAccess";
    static final String ERROR_NOT_AUTHENTICATED = "factor.webauthn.not_authenticated";
    static final String ERROR_PERMISSION_DENIED = "factor.webauthn.permission_denied";
    static final String ERROR_INTERNAL = "factor.webauthn.internal_error";

    private WebAuthnAdminAccess() {
        // utility
    }

    static JCRSessionWrapper requireSiteAdmin(String siteKey) {
        JahiaUser user = JCRSessionFactory.getInstance().getCurrentUser();
        if (user == null) {
            throw new DataFetchingException(ERROR_NOT_AUTHENTICATED);
        }
        try {
            JCRSessionWrapper session = JCRSessionFactory.getInstance().getCurrentUserSession();
            if (!session.nodeExists("/sites/" + siteKey)) {
                throw new DataFetchingException(user.isRoot() ? ERROR_INTERNAL : ERROR_PERMISSION_DENIED);
            }
            JCRNodeWrapper siteNode = session.getNode("/sites/" + siteKey);
            if (!user.isRoot() && !siteNode.hasPermission(SITE_ADMIN_PERMISSION)) {
                throw new DataFetchingException(ERROR_PERMISSION_DENIED);
            }
            return session;
        } catch (RepositoryException e) {
            throw new DataFetchingException(ERROR_INTERNAL);
        }
    }
}
