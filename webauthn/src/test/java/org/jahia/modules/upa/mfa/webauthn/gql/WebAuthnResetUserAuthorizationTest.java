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
 * {@code root}'s passkeys. Only the site's OWN users are in scope; any other subject (every global
 * user) requires server administration, and an unknown user is an error rather than a green
 * "true".
 */
public class WebAuthnResetUserAuthorizationTest {

    private static final String ATTACKER_SITE = "minorSite";

    @Test
    public void siteAdminCannotResetAGlobalUser() throws Exception {
        WebAuthnCredentialStore credentialStore = mock(WebAuthnCredentialStore.class);
        WebAuthnFactorMutation mutation = mutationWith(credentialStore);

        try (MockedStatic<JCRSessionFactory> sessions = jahiaSession(false);
             MockedStatic<JahiaUserManagerService> users = userManager("root", "/users/ro/ot/root")) {

            try {
                mutation.resetUserWebauthn("root", ATTACKER_SITE);
                fail("a site administrator must not be able to reset a user outside the site's own tree");
            } catch (DataFetchingException e) {
                assertTrue("expected permission_denied, got: " + e.getMessage(),
                        e.getMessage().contains("permission_denied"));
            }
        }

        verify(credentialStore, never()).deleteAll(anyString());
    }

    @Test
    public void siteAdminMayResetTheSitesOwnUser() throws Exception {
        WebAuthnCredentialStore credentialStore = mock(WebAuthnCredentialStore.class);
        WebAuthnFactorMutation mutation = mutationWith(credentialStore);

        try (MockedStatic<JCRSessionFactory> sessions = jahiaSession(false);
             MockedStatic<JahiaUserManagerService> users =
                     userManager("bob", "/sites/" + ATTACKER_SITE + "/users/bo/b/bob")) {
            assertTrue(mutation.resetUserWebauthn("bob", ATTACKER_SITE));
        }

        verify(credentialStore).deleteAll("bob");
    }

    @Test
    public void unknownUserIsReportedInsteadOfSilentlySucceeding() throws Exception {
        WebAuthnCredentialStore credentialStore = mock(WebAuthnCredentialStore.class);
        WebAuthnFactorMutation mutation = mutationWith(credentialStore);

        try (MockedStatic<JCRSessionFactory> sessions = jahiaSession(true);
             MockedStatic<JahiaUserManagerService> users = userManager("typo", null)) {

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
