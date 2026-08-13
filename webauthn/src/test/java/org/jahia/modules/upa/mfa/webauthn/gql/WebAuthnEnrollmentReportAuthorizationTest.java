package org.jahia.modules.upa.mfa.webauthn.gql;

import org.jahia.modules.graphql.provider.dxm.DataFetchingException;
import org.jahia.modules.upa.mfa.webauthn.WebAuthnCredentialStore;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRSessionFactory;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.usermanager.JahiaUser;
import org.junit.Test;
import org.mockito.MockedStatic;

import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Authorization of {@code mfaWebauthn.enrollmentReport(siteKey, limit)} — the WebAuthn mirror of
 * {@code TotpEnrollmentReportAuthorizationTest}.
 * <p>
 * {@code buildRegistrationReport} scans {@code jnt:user} across the whole repository and takes no
 * site key, so gating it on {@code siteAdminAccess} over the site named in the argument gave the
 * administrator of any minor site the passkey status of every platform account, {@code root}
 * included: a list of the accounts a stolen password alone would unlock. A platform-wide answer
 * requires platform-wide rights.
 */
public class WebAuthnEnrollmentReportAuthorizationTest {

    private static final String SITE = "minorSite";

    @Test
    public void siteAdministratorCannotReadThePlatformWideReport() throws Exception {
        WebAuthnCredentialStore credentialStore = mock(WebAuthnCredentialStore.class);
        WebAuthnFactorQuery query = queryWith(credentialStore);

        try (MockedStatic<JCRSessionFactory> sessions = caller(false)) {
            try {
                query.enrollmentReport(SITE, 10);
                fail("a site administrator must not obtain the passkey status of every platform user");
            } catch (DataFetchingException e) {
                assertTrue("expected permission_denied, got: " + e.getMessage(),
                        e.getMessage().contains("permission_denied"));
            }
        }

        verify(credentialStore, never()).buildRegistrationReport(anyInt());
    }

    @Test
    public void serverAdministratorMayReadThePlatformWideReport() throws Exception {
        WebAuthnCredentialStore credentialStore = mock(WebAuthnCredentialStore.class);
        when(credentialStore.buildRegistrationReport(10)).thenReturn(
                new WebAuthnCredentialStore.RegistrationReport(3, 1, Arrays.asList("bob", "carol"), false));
        WebAuthnFactorQuery query = queryWith(credentialStore);

        try (MockedStatic<JCRSessionFactory> sessions = caller(true)) {
            WebAuthnEnrollmentReportResult report = query.enrollmentReport(SITE, 10);
            assertEquals(3, report.getTotalUsers());
            assertEquals(1, report.getRegisteredUsers());
        }

        verify(credentialStore).buildRegistrationReport(10);
    }

    // --- fixtures ---------------------------------------------------------------------------

    private static WebAuthnFactorQuery queryWith(WebAuthnCredentialStore credentialStore) {
        WebAuthnFactorQuery query = new WebAuthnFactorQuery();
        query.setCredentialStore(credentialStore);
        return query;
    }

    /** A non-root site administrator of {@code minorSite}; server administrator only on demand. */
    private static MockedStatic<JCRSessionFactory> caller(boolean serverAdmin) throws Exception {
        JahiaUser user = mock(JahiaUser.class);
        when(user.getName()).thenReturn("sitealice");
        when(user.isRoot()).thenReturn(false);

        JCRNodeWrapper siteNode = mock(JCRNodeWrapper.class);
        when(siteNode.hasPermission("siteAdminAccess")).thenReturn(true);
        JCRNodeWrapper rootNode = mock(JCRNodeWrapper.class);
        when(rootNode.hasPermission("administrationAccess")).thenReturn(serverAdmin);

        JCRSessionWrapper session = mock(JCRSessionWrapper.class);
        when(session.nodeExists("/sites/" + SITE)).thenReturn(true);
        when(session.getNode("/sites/" + SITE)).thenReturn(siteNode);
        when(session.getRootNode()).thenReturn(rootNode);

        JCRSessionFactory factory = mock(JCRSessionFactory.class);
        when(factory.getCurrentUser()).thenReturn(user);
        when(factory.getCurrentUserSession()).thenReturn(session);

        MockedStatic<JCRSessionFactory> statics = mockStatic(JCRSessionFactory.class);
        statics.when(JCRSessionFactory::getInstance).thenReturn(factory);
        return statics;
    }
}
