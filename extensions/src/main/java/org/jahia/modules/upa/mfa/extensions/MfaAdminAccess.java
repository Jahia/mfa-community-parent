package org.jahia.modules.upa.mfa.extensions;

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
 * Three gates live here, and admin operations must pick the right one:
 * <ul>
 *   <li>{@link #requireSiteAdmin} authorizes an action on the SITE (its per-site policy, its
 *       {@code .cfg}, its audit log) &mdash; the site is the whole subject of the operation;</li>
 *   <li>{@link #requireServerAdmin} authorizes an action whose reach is the whole PLATFORM (a
 *       repository-wide enrollment report). A site administrator holds no rights outside their
 *       site, so a platform-wide answer needs platform-wide rights;</li>
 *   <li>{@link #requireAdminForUser} authorizes an action on a USER, performed with a system
 *       session and therefore not covered by any JCR ACL. The site alone is NOT a sufficient
 *       authorization there: {@code resetUserMfa(userId, siteKey)} used to check only
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
     * Require server administration for a platform-wide read or write. Same error codes as
     * {@link #requireSiteAdmin}; fails CLOSED on a repository error.
     *
     * @param errorPrefix the factor's error-code prefix (e.g. {@code "factor.totp."})
     * @return the caller's JCR session
     */
    public static JCRSessionWrapper requireServerAdmin(String errorPrefix) {
        JahiaUser user = JCRSessionFactory.getInstance().getCurrentUser();
        if (user == null) {
            throw new DataFetchingException(errorPrefix + "not_authenticated");
        }
        JCRSessionWrapper session;
        try {
            session = JCRSessionFactory.getInstance().getCurrentUserSession();
        } catch (RepositoryException e) {
            throw new DataFetchingException(errorPrefix + "internal_error");
        }
        if (!isServerAdministrator(session, errorPrefix)) {
            throw new DataFetchingException(errorPrefix + "permission_denied");
        }
        return session;
    }

    /**
     * Authorize an admin operation on a TARGET USER that runs outside any JCR ACL (a system-session
     * write such as "clear this user's second factor"), and resolve that user ONCE so the
     * authorization and the write cannot act on two different accounts. Checked in this order:
     * <ol>
     *   <li>the caller is root or a site administrator of {@code siteKey}
     *       ({@link #requireSiteAdmin}) &mdash; the site frames and audits the operation;</li>
     *   <li>the caller holds {@link #SERVER_ADMIN_PERMISSION} (see below);</li>
     *   <li>{@code userId} actually EXISTS in the tree the write will search &mdash; an unknown
     *       user is rejected with {@code <prefix>user_not_found} instead of silently succeeding,
     *       which used to hand a helpdesk a green confirmation while the real (mistyped) user
     *       stayed locked out.</li>
     * </ol>
     *
     * <h4>Why server administration is required for EVERY subject</h4>
     * The first fix for the takeover above let a site administrator through for the site's OWN users
     * ({@code /sites/<siteKey>/users/...}), resolved with
     * {@code JahiaUserManagerService.lookupUser(userId, siteKey)} &mdash; which searches the global
     * tree first, then the site's. But every MFA store in these modules resolves its subject with
     * {@code lookupUser(userId, session)}, i.e. {@code /users/} ONLY: enrollment, verification,
     * grace tracking, lockout counters and the reset itself. A site-scoped user therefore cannot
     * hold MFA state in this module <em>at all</em>, and the two resolutions could only disagree in
     * one direction:
     * <ul>
     *   <li>a global user (every account that can actually own a factor) was never "the site's own",
     *       so a site administrator was denied EVERY reset &mdash; the documented helpdesk recovery
     *       path was closed without saying so;</li>
     *   <li>a site-scoped user passed authorization and the write then found nothing: {@code
     *       disable()} returned quietly, the lockout counters of an untouched account were cleared,
     *       and the mutation answered {@code true} &mdash; the silent success this gate exists to
     *       remove.</li>
     * </ul>
     * So the branch that was supposed to keep site administrators working could never succeed. It is
     * gone: the subject is resolved with {@link JahiaUserManagerService#lookupUser(String)}, the
     * SAME global lookup the stores use, and because every subject is a platform account, acting on
     * one requires platform rights. Site administrators must escalate to a server administrator for
     * an MFA reset (README, <i>Lockout &amp; recovery</i>). Supporting site-scoped users would mean
     * making every store method site-aware, not relaxing this gate.
     *
     * @param userId      the target user (the SUBJECT of the operation)
     * @param siteKey     the site the operation is performed and audited under
     * @param errorPrefix the factor's error-code prefix (e.g. {@code "factor.totp."}); the
     *                    surfaced codes are those of {@link #requireSiteAdmin} plus
     *                    {@code <prefix>user_not_found}
     * @return the resolved subject; the caller must act on {@link Subject#getUserId()} and no other
     *         identifier
     */
    public static Subject requireAdminForUser(String userId, String siteKey, String errorPrefix) {
        JCRSessionWrapper session = requireSiteAdmin(siteKey, errorPrefix);
        // Rights BEFORE existence: reporting user_not_found to a caller who may not act on any
        // subject anyway would turn this gate into a global username oracle for site administrators.
        if (!isServerAdministrator(session, errorPrefix)) {
            throw new DataFetchingException(errorPrefix + "permission_denied");
        }
        // The SAME resolution the write performs (system-session, global tree), so authorization and
        // action can never land on two different accounts.
        JCRUserNode target = JahiaUserManagerService.getInstance().lookupUser(userId);
        if (target == null) {
            throw new DataFetchingException(errorPrefix + "user_not_found");
        }
        return new Subject(session, target.getName(), target.getPath());
    }

    /**
     * A subject resolved by {@link #requireAdminForUser}: the account the caller is authorized to
     * act on, carried to the action so it cannot re-resolve a different one. {@link #getUserId()} is
     * the resolved node's own name (not the string the client sent) and {@link #getUserPath()} the
     * node it came from, which admin operations record in their audit detail.
     */
    public static final class Subject {

        private final JCRSessionWrapper callerSession;
        private final String userId;
        private final String userPath;

        Subject(JCRSessionWrapper callerSession, String userId, String userPath) {
            this.callerSession = callerSession;
            this.userId = userId;
            this.userPath = userPath;
        }

        /** The caller's JCR session (writes on the SITE should reuse it). */
        public JCRSessionWrapper getCallerSession() {
            return callerSession;
        }

        /** The resolved user id: the only identifier the action may pass to the stores. */
        public String getUserId() {
            return userId;
        }

        /** The resolved user's JCR path (for audit / diagnostics). */
        public String getUserPath() {
            return userPath;
        }
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
