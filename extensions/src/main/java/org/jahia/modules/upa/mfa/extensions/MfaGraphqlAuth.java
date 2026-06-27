package org.jahia.modules.upa.mfa.extensions;

import org.jahia.services.content.JCRSessionFactory;
import org.jahia.services.usermanager.JahiaUser;
import org.jahia.services.usermanager.JahiaUserManagerService;

/**
 * Shared current-user resolution for the factor GraphQL resolvers. Centralizes the
 * guest-vs-authenticated distinction every factor's mutation and query needs.
 * <p>
 * CRITICAL: Jahia resolves unauthenticated GraphQL requests to the GUEST user, not to
 * {@code null} &mdash; treating guest as authenticated would silently run self-service operations
 * against the literal {@code guest} account (and bypass the pre-auth enrollment guard).
 */
public final class MfaGraphqlAuth {

    private MfaGraphqlAuth() {
        // utility
    }

    /** The authenticated (non-guest) caller, or {@code null} when the request is anonymous/guest. */
    public static JahiaUser currentNonGuestUser() {
        JahiaUser user = JCRSessionFactory.getInstance().getCurrentUser();
        return (user == null || JahiaUserManagerService.isGuest(user)) ? null : user;
    }

    /** The current user's name for audit attribution, or {@code "<anonymous>"} when none. */
    public static String currentUserName() {
        JahiaUser u = JCRSessionFactory.getInstance().getCurrentUser();
        return u == null ? "<anonymous>" : u.getName();
    }
}
