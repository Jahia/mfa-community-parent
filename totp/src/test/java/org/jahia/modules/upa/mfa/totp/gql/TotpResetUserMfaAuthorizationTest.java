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
 * takeover. The site must authorize only the site's OWN users; anyone else (every global user,
 * {@code root} included) requires server administration. A {@code userId} that does not exist at
 * all is now an error rather than a green "true" that leaves the real user locked out.
 * <p>
 * The mutation is fronted by Jahia statics ({@code JCRSessionFactory} /
 * {@code JahiaUserManagerService}); mockito-inline stands them up, as in the JCR-bound store tests.
 */
public class TotpResetUserMfaAuthorizationTest {

    private static final String ATTACKER_SITE = "minorSite";
    private static final String ADMIN = "sitealice";

    @Test
    public void siteAdminCannotResetAGlobalUser() throws Exception {
        TotpUserStore userStore = mock(TotpUserStore.class);
        TotpFactorMutation mutation = mutationWith(userStore);

        try (MockedStatic<JCRSessionFactory> sessions = jahiaSession(false);
             MockedStatic<JahiaUserManagerService> users = userManager("root", "/users/ro/ot/root")) {

            try {
                mutation.resetUserMfa("root", ATTACKER_SITE);
                fail("a site administrator must not be able to reset a user outside the site's own tree");
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
        // The legitimate recovery path stays open: server administration authorizes any subject.
        TotpUserStore userStore = mock(TotpUserStore.class);
        TotpFactorMutation mutation = mutationWith(userStore);

        try (MockedStatic<JCRSessionFactory> sessions = jahiaSession(true);
             MockedStatic<JahiaUserManagerService> users = userManager("root", "/users/ro/ot/root")) {
            assertTrue(mutation.resetUserMfa("root", ATTACKER_SITE));
        }

        verify(userStore).disable("root");
        verify(userStore).clearGrace("root");
    }

    @Test
    public void siteAdminMayResetTheSitesOwnUser() throws Exception {
        // The everyday helpdesk case must keep working: a user that lives in the site's own tree.
        TotpUserStore userStore = mock(TotpUserStore.class);
        TotpFactorMutation mutation = mutationWith(userStore);

        try (MockedStatic<JCRSessionFactory> sessions = jahiaSession(false);
             MockedStatic<JahiaUserManagerService> users =
                     userManager("bob", "/sites/" + ATTACKER_SITE + "/users/bo/b/bob")) {
            assertTrue(mutation.resetUserMfa("bob", ATTACKER_SITE));
        }

        verify(userStore).disable("bob");
    }

    @Test
    public void unknownUserIsReportedInsteadOfSilentlySucceeding() throws Exception {
        TotpUserStore userStore = mock(TotpUserStore.class);
        TotpFactorMutation mutation = mutationWith(userStore);

        try (MockedStatic<JCRSessionFactory> sessions = jahiaSession(true);
             MockedStatic<JahiaUserManagerService> users = userManager("typo", null)) {

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
        TotpFactorMutation mutation = new TotpFactorMutation();
        mutation.setUserStore(userStore);
        mutation.setRateLimiter(mock(TotpManagementRateLimiter.class));
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

    /** The target user resolution: {@code userPath == null} stands for "no such user". */
    private static MockedStatic<JahiaUserManagerService> userManager(String userId, String userPath) {
        JahiaUserManagerService service = mock(JahiaUserManagerService.class);
        if (userPath != null) {
            JCRUserNode target = mock(JCRUserNode.class);
            when(target.getPath()).thenReturn(userPath);
            when(service.lookupUser(userId, ATTACKER_SITE)).thenReturn(target);
        }
        MockedStatic<JahiaUserManagerService> statics = mockStatic(JahiaUserManagerService.class);
        statics.when(JahiaUserManagerService::getInstance).thenReturn(service);
        return statics;
    }
}
