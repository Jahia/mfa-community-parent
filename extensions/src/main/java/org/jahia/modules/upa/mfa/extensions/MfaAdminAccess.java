package org.jahia.modules.upa.mfa.extensions;

import org.apache.commons.lang3.StringUtils;
import org.jahia.modules.graphql.provider.dxm.DataFetchingException;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRSessionFactory;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.content.decorator.JCRUserNode;
import org.jahia.services.usermanager.JahiaUser;
import org.jahia.services.usermanager.JahiaUserManagerService;

import javax.jcr.RepositoryException;

/**
 * Shared site-administration permission gate for every factor's per-site / admin GraphQL
 * operations. The up-front {@code hasPermission} check yields a friendly, factor-specific error;
 * the JCR ACL on the write remains the load-bearing guard. Each factor passes its own error-code
 * prefix (e.g. {@code "factor.totp."}) so the surfaced error matches its message catalog.
 * <p>
 * Two gates live here, and admin operations must pick the right one:
 * <ul>
 *   <li>{@link #requireSiteAdmin} authorizes an action on the SITE (its per-site policy, its
 *       {@code .cfg}) &mdash; the site is the whole subject of the operation;</li>
 *   <li>{@link #requireSiteAdminForUser} authorizes an action on a USER, performed with a
 *       system session and therefore not covered by any JCR ACL. The site alone is NOT a
 *       sufficient authorization there: {@code resetUserMfa(userId, siteKey)} used to check only
 *       {@code siteAdminAccess} on {@code /sites/<siteKey>} and then strip the second factor of an
 *       arbitrary, unconstrained {@code userId} &mdash; so the administrator of any minor site
 *       could disable {@code root}'s MFA (and clear its lockout counters) and, with a stolen or
 *       phished password, take over the platform. The SUBJECT must be authorized too.</li>
 * </ul>
 */
public final class MfaAdminAccess {

    public static final String SITE_ADMIN_PERMISSION = "siteAdminAccess";

    /**
     * Jahia's server-administration permission (the one guarding {@code administration} mode),
     * checked on the repository root. Required to act on a user that is not one of the site's own.
     */
    public static final String SERVER_ADMIN_PERMISSION = "administrationAccess";

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

    /**
     * Require site administration on {@code siteKey} AND authorization over the TARGET USER for an
     * admin operation that runs outside any JCR ACL (a system-session write such as "clear this
     * user's second factor"). Three things are checked, in this order:
     * <ol>
     *   <li>the caller is root or a site administrator of {@code siteKey}
     *       ({@link #requireSiteAdmin});</li>
     *   <li>{@code userId} actually EXISTS &mdash; an unknown user is rejected with
     *       {@code <prefix>user_not_found} instead of silently succeeding, which used to hand a
     *       helpdesk a green confirmation while the real (mistyped) user stayed locked out;</li>
     *   <li>the target user is one of the site's OWN users ({@code /sites/<siteKey>/users/...}),
     *       i.e. an account that site administration legitimately owns. A user living outside that
     *       tree &mdash; every global user, {@code root} included &mdash; belongs to the platform,
     *       not to one site, so acting on it requires {@link #SERVER_ADMIN_PERMISSION}.</li>
     * </ol>
     *
     * @param userId      the target user (the SUBJECT of the operation)
     * @param siteKey     the site the caller claims administration over
     * @param errorPrefix the factor's error-code prefix (e.g. {@code "factor.totp."}); the
     *                    surfaced codes are those of {@link #requireSiteAdmin} plus
     *                    {@code <prefix>user_not_found}
     * @return the caller's JCR session (writes should reuse it)
     */
    public static JCRSessionWrapper requireSiteAdminForUser(String userId, String siteKey, String errorPrefix) {
        JCRSessionWrapper session = requireSiteAdmin(siteKey, errorPrefix);
        // Resolve through the SYSTEM-session lookup (global users first, then the site's own): the
        // subject must be identified independently of what the caller happens to be able to see,
        // otherwise a site admin who cannot read /users/root would get "not found" for root and the
        // scope decision below would be made on a wrong premise.
        JCRUserNode target = JahiaUserManagerService.getInstance().lookupUser(userId, siteKey);
        if (target == null) {
            throw new DataFetchingException(errorPrefix + "user_not_found");
        }
        if (isScopedToSite(target.getPath(), siteKey)) {
            return session;
        }
        if (!isServerAdministrator(session, errorPrefix)) {
            throw new DataFetchingException(errorPrefix + "permission_denied");
        }
        return session;
    }

    /**
     * Whether the user's JCR path lies inside the site's OWN user tree
     * ({@code /sites/<siteKey>/users/...}). Package-visible for tests.
     */
    static boolean isScopedToSite(String userPath, String siteKey) {
        if (StringUtils.isBlank(userPath) || StringUtils.isBlank(siteKey)) {
            return false;
        }
        return userPath.startsWith("/sites/" + siteKey + "/users/");
    }

    /**
     * Whether the caller may administer the whole platform: root, or holder of
     * {@link #SERVER_ADMIN_PERMISSION} on the repository root. Fails CLOSED &mdash; a repository
     * error surfaces {@code <prefix>internal_error} rather than granting the right.
     */
    private static boolean isServerAdministrator(JCRSessionWrapper session, String errorPrefix) {
        JahiaUser user = JCRSessionFactory.getInstance().getCurrentUser();
        if (user != null && user.isRoot()) {
            return true;
        }
        try {
            return session.getRootNode().hasPermission(SERVER_ADMIN_PERMISSION);
        } catch (RepositoryException e) {
            throw new DataFetchingException(errorPrefix + "internal_error");
        }
    }
}
