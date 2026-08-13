package org.jahia.modules.upa.mfa.totp.gql;

import org.jahia.modules.upa.mfa.extensions.MfaAdminAccess;
import org.jahia.services.content.JCRSessionWrapper;

/**
 * Site-administration permission gate for the per-site / admin TOTP GraphQL operations. Thin
 * wrapper over the shared {@link MfaAdminAccess}, binding the TOTP error-code prefix so the
 * surfaced errors match the TOTP message catalog.
 */
final class TotpAdminAccess {

    /** Error-code prefix for this factor; the shared gate appends not_authenticated/permission_denied/internal_error. */
    static final String ERROR_PREFIX = "factor.totp.";

    private TotpAdminAccess() {
        // utility
    }

    /**
     * Require that the current user is root or holds {@code siteAdminAccess} on the given site.
     * Returns the caller's JCR session for convenience (writes should reuse it).
     */
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
