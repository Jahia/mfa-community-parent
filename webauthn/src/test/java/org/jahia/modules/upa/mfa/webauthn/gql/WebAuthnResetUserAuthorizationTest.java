package org.jahia.modules.upa.mfa.webauthn.gql;

import org.jahia.modules.graphql.provider.dxm.DataFetchingException;
import org.jahia.modules.upa.mfa.webauthn.WebAuthnAuditLog;
import org.jahia.modules.upa.mfa.webauthn.WebAuthnCredentialStore;
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
 * Authorization of the SUBJECT of {@code resetUserWebauthn(userId, siteKey)} — the WebAuthn mirror
 * of the TOTP admin-recovery gate. It deletes ALL of a user's authenticators with a SYSTEM session,
 * so authorizing on {@code siteKey} alone let the administrator of any minor site clear
 * {@code root}'s passkeys.
 * <p>
 * The same two properties as {@code TotpResetUserMfaAuthorizationTest}: site administration alone
 * never authorizes a subject (every account that can hold a passkey here is a platform user), and
 * the subject is resolved ONCE with {@code lookupUser(userId)} — the global lookup
 * {@code WebAuthnCredentialStore} itself uses — so authorization and deletion cannot land on two
 * different accounts, and a subject the store could never find is an error instead of a green
 * {@code true}.
 */
public class WebAuthnResetUserAuthorizationTest {

    private static final String ATTACKER_SITE = "minorSite";

    @Test
    public void siteAdminCannotResetAUser() throws Exception {
        WebAuthnCredentialStore credentialStore = mock(WebAuthnCredentialStore.class);
        WebAuthnFactorMutation mutation = mutationWith(credentialStore);

        try (MockedStatic<JCRSessionFactory> sessions = jahiaSession(false);
             MockedStatic<JahiaUserManagerService> users = globalUser("root", "/users/ro/ot/root")) {

            try {
                mutation.resetUserWebauthn("root", ATTACKER_SITE);
                fail("a site administrator must not be able to clear a platform user's passkeys");
            } catch (DataFetchingException e) {
                assertTrue("expected permission_denied, got: " + e.getMessage(),
                        e.getMessage().contains("permission_denied"));
            }
        }

        verify(credentialStore, never()).deleteAll(anyString());
    }

    @Test
    public void serverAdministratorMayResetAGlobalUser() throws Exception {
        WebAuthnCredentialStore credentialStore = mock(WebAuthnCredentialStore.class);
        WebAuthnFactorMutation mutation = mutationWith(credentialStore);

        try (MockedStatic<JCRSessionFactory> sessions = jahiaSession(true);
             MockedStatic<JahiaUserManagerService> users = globalUser("root", "/users/ro/ot/root")) {
            assertTrue(mutation.resetUserWebauthn("root", ATTACKER_SITE));
        }

        verify(credentialStore).deleteAll("root");
        verify(credentialStore).clearGrace("root");
    }

    @Test
    public void aSiteScopedUserIsReportedInsteadOfBeingSilentlyReportedAsReset() throws Exception {
        // Authorization deliberately satisfied (a server administrator) so that only the RESOLUTION
        // is under test: 'bob' exists solely under /sites/minorSite/users/..., which the store's
        // global lookup cannot see. Acting anyway deleted nothing and still answered "true".
        WebAuthnCredentialStore credentialStore = mock(WebAuthnCredentialStore.class);
        WebAuthnFactorMutation mutation = mutationWith(credentialStore);

        try (MockedStatic<JCRSessionFactory> sessions = jahiaSession(true);
             MockedStatic<JahiaUserManagerService> users =
                     siteScopedUser("bob", "/sites/" + ATTACKER_SITE + "/users/bo/b/bob")) {

            try {
                mutation.resetUserWebauthn("bob", ATTACKER_SITE);
                fail("a subject the write cannot resolve must not return a green confirmation");
            } catch (DataFetchingException e) {
                assertTrue("expected user_not_found, got: " + e.getMessage(),
                        e.getMessage().contains("user_not_found"));
            }
        }

        verify(credentialStore, never()).deleteAll(anyString());
        verify(credentialStore, never()).clearGrace(anyString());
    }

    @Test
    public void unknownUserIsReportedInsteadOfSilentlySucceeding() throws Exception {
        WebAuthnCredentialStore credentialStore = mock(WebAuthnCredentialStore.class);
        WebAuthnFactorMutation mutation = mutationWith(credentialStore);

        try (MockedStatic<JCRSessionFactory> sessions = jahiaSession(true);
             MockedStatic<JahiaUserManagerService> users = noSuchUser()) {

            try {
                mutation.resetUserWebauthn("typo", ATTACKER_SITE);
                fail("a mistyped user must not return a green confirmation");
            } catch (DataFetchingException e) {
                assertTrue("expected user_not_found, got: " + e.getMessage(),
                        e.getMessage().contains("user_not_found"));
            }
        }

        verify(credentialStore, never()).deleteAll(anyString());
    }

    // --- fixtures ---------------------------------------------------------------------------

    private static WebAuthnFactorMutation mutationWith(WebAuthnCredentialStore credentialStore) {
        WebAuthnFactorMutation mutation = new WebAuthnFactorMutation();
        mutation.setCredentialStore(credentialStore);
        mutation.setAuditLog(mock(WebAuthnAuditLog.class));
        return mutation;
    }

    /** The caller: a non-root site administrator of {@code minorSite}; server admin only on demand. */
    private static MockedStatic<JCRSessionFactory> jahiaSession(boolean serverAdmin) throws Exception {
        JahiaUser caller = mock(JahiaUser.class);
        when(caller.getName()).thenReturn("sitealice");
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
     * A user of the platform tree ({@code /users/...}): found by BOTH the global lookup the store
     * uses and the site-aware one (which checks the global tree first).
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
     * the global lookup the store uses does not.
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
