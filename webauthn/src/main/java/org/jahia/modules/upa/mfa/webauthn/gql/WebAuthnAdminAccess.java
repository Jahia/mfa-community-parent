package org.jahia.modules.upa.mfa.webauthn.gql;

import org.jahia.modules.upa.mfa.extensions.MfaAdminAccess;
import org.jahia.services.content.JCRSessionWrapper;

/**
 * Site-administration permission gate for the per-site / admin WebAuthn GraphQL operations. Thin
 * wrapper over the shared {@link MfaAdminAccess}, binding the WebAuthn error-code prefix.
 */
final class WebAuthnAdminAccess {

    /** Error-code prefix for this factor; the shared gate appends not_authenticated/permission_denied/internal_error. */
    static final String ERROR_PREFIX = "factor.webauthn.";

    private WebAuthnAdminAccess() {
        // utility
    }

    static JCRSessionWrapper requireSiteAdmin(String siteKey) {
        return MfaAdminAccess.requireSiteAdmin(siteKey, ERROR_PREFIX);
    }

    /**
     * Require site administration on {@code siteKey} AND authorization over the target user for an
     * operation that acts on that user with a system session (the admin reset). The site alone
     * never authorizes a subject outside its own user tree &mdash; see
     * {@link MfaAdminAccess#requireSiteAdminForUser}.
     */
    static JCRSessionWrapper requireSiteAdminForUser(String userId, String siteKey) {
        return MfaAdminAccess.requireSiteAdminForUser(userId, siteKey, ERROR_PREFIX);
    }
}
