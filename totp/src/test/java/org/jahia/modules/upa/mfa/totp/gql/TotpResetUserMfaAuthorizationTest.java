package org.jahia.modules.upa.mfa.totp.gql;

import org.jahia.modules.graphql.provider.dxm.DataFetchingException;
import org.jahia.modules.upa.mfa.totp.TotpAuditLog;
import org.jahia.modules.upa.mfa.totp.TotpManagementRateLimiter;
import org.jahia.modules.upa.mfa.totp.TotpUserStore;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRSessionFactory;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.content.decorator.JCRUserNode;
import org.jahia.services.usermanager.JahiaUser;
import org.jahia.services.usermanager.JahiaUserManagerService;
import org.junit.Test;
import org.mockito.MockedStatic;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Authorization of the SUBJECT of {@code resetUserMfa(userId, siteKey)} — the admin-recovery
 * mutation that clears a user's TOTP enrollment (and its lockout counters) with a SYSTEM session,
 * i.e. outside any JCR ACL.
 * <p>
 * It used to authorize on {@code siteKey} alone ({@code siteAdminAccess} on
 * {@code /sites/<siteKey>}) and then act on an unconstrained {@code userId}: the administrator of
 * any minor site could call {@code resetUserMfa(userId: "root", siteKey: "<their own site>")} and
 * strip the platform super-user's second factor, turning a stolen or phished password into a full
 * takeover.
 * <p>
 * The fix for that then authorized the subject with a DIFFERENT resolution than the one the write
 * uses: {@code lookupUser(userId, siteKey)} (site tree included) to decide, {@code lookupUser(userId,
 * session)} (GLOBAL ONLY, what every store method does) to act. The two could disagree — for a
 * user living under {@code /sites/<key>/users/...} authorization passed and the write then found
 * nothing, so {@code disable()} returned quietly and the mutation reported {@code true} on a user it
 * had never touched. These tests pin the single resolution: the subject is resolved ONCE, with the
 * global lookup the stores use, and that resolved user is what gets reset — or the call fails.
 * <p>
 * The mutation is fronted by Jahia statics ({@code JCRSessionFactory} /
 * {@code JahiaUserManagerService}); mockito-inline stands them up, as in the JCR-bound store tests.
 */
public class TotpResetUserMfaAuthorizationTest {

    private static final String ATTACKER_SITE = "minorSite";
    private static final String ADMIN = "sitealice";

    @Test
    public void siteAdminCannotResetAUser() throws Exception {
        // Every user this module can hold MFA for is a GLOBAL user (all stores resolve through the
        // global lookup), so site administration is never sufficient for the subject of a reset.
        TotpUserStore userStore = mock(TotpUserStore.class);
        TotpFactorMutation mutation = mutationWith(userStore);

        try (MockedStatic<JCRSessionFactory> sessions = jahiaSession(false);
             MockedStatic<JahiaUserManagerService> users = globalUser("root", "/users/ro/ot/root")) {

            try {
                mutation.resetUserMfa("root", ATTACKER_SITE);
                fail("a site administrator must not be able to reset a platform user's second factor");
            } catch (DataFetchingException e) {
                assertTrue("expected permission_denied, got: " + e.getMessage(),
                        e.getMessage().contains("permission_denied"));
            }
        }

        verify(userStore, never()).disable(anyString());
        verify(userStore, never()).clearGrace(anyString());
    }

    @Test
    public void serverAdministratorMayResetAGlobalUser() throws Exception {
        // The legitimate recovery path: server administration authorizes any subject.
        TotpUserStore userStore = mock(TotpUserStore.class);
        TotpFactorMutation mutation = mutationWith(userStore);

        try (MockedStatic<JCRSessionFactory> sessions = jahiaSession(true);
             MockedStatic<JahiaUserManagerService> users = globalUser("root", "/users/ro/ot/root")) {
            assertTrue(mutation.resetUserMfa("root", ATTACKER_SITE));
        }

        verify(userStore).disable("root");
        verify(userStore).clearGrace("root");
    }

    @Test
    public void aSiteScopedUserIsReportedInsteadOfBeingSilentlyReportedAsReset() throws Exception {
        // The divergence bug, with the authorization deliberately satisfied (a server administrator)
        // so that only the RESOLUTION is under test: 'bob' exists solely under
        // /sites/minorSite/users/..., which the store's global lookup cannot see. Acting anyway
        // cleared nothing, cleared the lockout counters of a user that was never touched, and still
        // answered "true" to the helpdesk.
        TotpUserStore userStore = mock(TotpUserStore.class);
        TotpManagementRateLimiter rateLimiter = mock(TotpManagementRateLimiter.class);
        TotpFactorMutation mutation = mutationWith(userStore, rateLimiter);

        try (MockedStatic<JCRSessionFactory> sessions = jahiaSession(true);
             MockedStatic<JahiaUserManagerService> users =
                     siteScopedUser("bob", "/sites/" + ATTACKER_SITE + "/users/bo/b/bob")) {

            try {
                mutation.resetUserMfa("bob", ATTACKER_SITE);
                fail("a subject the write cannot resolve must not return a green confirmation");
            } catch (DataFetchingException e) {
                assertTrue("expected user_not_found, got: " + e.getMessage(),
                        e.getMessage().contains("user_not_found"));
            }
        }

        verify(userStore, never()).disable(anyString());
        verify(userStore, never()).clearGrace(anyString());
        verify(rateLimiter, never()).recordSuccess(anyString());
    }

    @Test
    public void unknownUserIsReportedInsteadOfSilentlySucceeding() throws Exception {
        TotpUserStore userStore = mock(TotpUserStore.class);
        TotpFactorMutation mutation = mutationWith(userStore);

        try (MockedStatic<JCRSessionFactory> sessions = jahiaSession(true);
             MockedStatic<JahiaUserManagerService> users = noSuchUser()) {

            try {
                mutation.resetUserMfa("typo", ATTACKER_SITE);
                fail("a mistyped user must not return a green confirmation");
            } catch (DataFetchingException e) {
                assertTrue("expected user_not_found, got: " + e.getMessage(),
                        e.getMessage().contains("user_not_found"));
            }
        }

        verify(userStore, never()).disable(anyString());
    }

    // --- fixtures ---------------------------------------------------------------------------

    private static TotpFactorMutation mutationWith(TotpUserStore userStore) {
        return mutationWith(userStore, mock(TotpManagementRateLimiter.class));
    }

    private static TotpFactorMutation mutationWith(TotpUserStore userStore,
                                                   TotpManagementRateLimiter rateLimiter) {
        TotpFactorMutation mutation = new TotpFactorMutation();
        mutation.setUserStore(userStore);
        mutation.setRateLimiter(rateLimiter);
        mutation.setAuditLog(mock(TotpAuditLog.class));
        return mutation;
    }

    /**
     * The caller: an authenticated non-root user holding {@code siteAdminAccess} on
     * {@code /sites/minorSite}, and holding {@code administrationAccess} on the repository root
     * only when {@code serverAdmin} is {@code true}.
     */
    private static MockedStatic<JCRSessionFactory> jahiaSession(boolean serverAdmin) throws Exception {
        JahiaUser caller = mock(JahiaUser.class);
        when(caller.getName()).thenReturn(ADMIN);
        when(caller.isRoot()).thenReturn(false);

        JCRNodeWrapper siteNode = mock(JCRNodeWrapper.class);
        when(siteNode.hasPermission("siteAdminAccess")).thenReturn(true);
        JCRNodeWrapper rootNode = mock(JCRNodeWrapper.class);
        when(rootNode.hasPermission("administrationAccess")).thenReturn(serverAdmin);

        JCRSessionWrapper session = mock(JCRSessionWrapper.class);
        when(session.nodeExists("/sites/" + ATTACKER_SITE)).thenReturn(true);
        when(session.getNode("/sites/" + ATTACKER_SITE)).thenReturn(siteNode);
        when(session.getRootNode()).thenReturn(rootNode);

        JCRSessionFactory factory = mock(JCRSessionFactory.class);
        when(factory.getCurrentUser()).thenReturn(caller);
        when(factory.getCurrentUserSession()).thenReturn(session);

        MockedStatic<JCRSessionFactory> statics = mockStatic(JCRSessionFactory.class);
        statics.when(JCRSessionFactory::getInstance).thenReturn(factory);
        return statics;
    }

    /**
     * A user of the platform tree ({@code /users/...}): found by BOTH the global lookup the stores
     * use and the site-aware one (which checks the global tree first).
     */
    private static MockedStatic<JahiaUserManagerService> globalUser(String userId, String userPath) {
        JahiaUserManagerService service = mock(JahiaUserManagerService.class);
        JCRUserNode target = userNode(userId, userPath);
        when(service.lookupUser(userId)).thenReturn(target);
        when(service.lookupUser(userId, ATTACKER_SITE)).thenReturn(target);
        return statics(service);
    }

    /**
     * A user living ONLY under {@code /sites/<siteKey>/users/...}: the site-aware lookup finds it,
     * the global lookup every store method uses does not.
     */
    private static MockedStatic<JahiaUserManagerService> siteScopedUser(String userId, String userPath) {
        JahiaUserManagerService service = mock(JahiaUserManagerService.class);
        // Build the node BEFORE opening the stubbing: creating a mock inside when(...).thenReturn(...)
        // trips Mockito's unfinished-stubbing detection.
        JCRUserNode target = userNode(userId, userPath);
        when(service.lookupUser(userId, ATTACKER_SITE)).thenReturn(target);
        return statics(service);
    }

    /** No user of that name anywhere. */
    private static MockedStatic<JahiaUserManagerService> noSuchUser() {
        return statics(mock(JahiaUserManagerService.class));
    }

    private static JCRUserNode userNode(String userId, String userPath) {
        JCRUserNode node = mock(JCRUserNode.class);
        when(node.getName()).thenReturn(userId);
        when(node.getPath()).thenReturn(userPath);
        return node;
    }

    private static MockedStatic<JahiaUserManagerService> statics(JahiaUserManagerService service) {
        MockedStatic<JahiaUserManagerService> statics = mockStatic(JahiaUserManagerService.class);
        statics.when(JahiaUserManagerService::getInstance).thenReturn(service);
        return statics;
    }
}
