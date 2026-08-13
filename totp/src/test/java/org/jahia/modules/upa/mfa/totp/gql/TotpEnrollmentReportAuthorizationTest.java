package org.jahia.modules.upa.mfa.totp.gql;

import org.jahia.modules.graphql.provider.dxm.DataFetchingException;
import org.jahia.modules.upa.mfa.totp.TotpUserStore;
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
 * Authorization of {@code mfaTotp.enrollmentReport(siteKey, limit)}.
 * <p>
 * The report is built by {@code TotpUserStore.buildEnrollmentReport}, which scans {@code jnt:user}
 * across the WHOLE repository — the method takes no site key and enrollment is a global property.
 * Gating it on {@code siteAdminAccess} over the site named in the argument therefore handed the
 * administrator of any minor site the MFA-enrollment status of every account on the platform,
 * {@code root} included: a ready-made list of the accounts protected by a password alone, which is
 * exactly the targeting information the {@code resetUserMfa} gate was hardened to withhold.
 * <p>
 * A platform-wide answer requires platform-wide rights. The site argument is still checked (it
 * frames the request and keeps the error for a bogus site key), but it no longer authorizes the
 * read.
 */
public class TotpEnrollmentReportAuthorizationTest {

    private static final String SITE = "minorSite";

    @Test
    public void siteAdministratorCannotReadThePlatformWideReport() throws Exception {
        TotpUserStore userStore = mock(TotpUserStore.class);
        TotpFactorQuery query = queryWith(userStore);

        try (MockedStatic<JCRSessionFactory> sessions = caller(false)) {
            try {
                query.enrollmentReport(SITE, 10);
                fail("a site administrator must not obtain the enrollment status of every platform user");
            } catch (DataFetchingException e) {
                assertTrue("expected permission_denied, got: " + e.getMessage(),
                        e.getMessage().contains("permission_denied"));
            }
        }

        verify(userStore, never()).buildEnrollmentReport(anyInt());
    }

    @Test
    public void serverAdministratorMayReadThePlatformWideReport() throws Exception {
        TotpUserStore userStore = mock(TotpUserStore.class);
        when(userStore.buildEnrollmentReport(10)).thenReturn(
                new TotpUserStore.EnrollmentReport(3, 1, Arrays.asList("bob", "carol"), false));
        TotpFactorQuery query = queryWith(userStore);

        try (MockedStatic<JCRSessionFactory> sessions = caller(true)) {
            TotpEnrollmentReportResult report = query.enrollmentReport(SITE, 10);
            assertEquals(3, report.getTotalUsers());
            assertEquals(1, report.getEnrolledUsers());
        }

        verify(userStore).buildEnrollmentReport(10);
    }

    // --- fixtures ---------------------------------------------------------------------------

    private static TotpFactorQuery queryWith(TotpUserStore userStore) {
        TotpFactorQuery query = new TotpFactorQuery();
        query.setUserStore(userStore);
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
