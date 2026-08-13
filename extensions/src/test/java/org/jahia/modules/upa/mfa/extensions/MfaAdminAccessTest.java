package org.jahia.modules.upa.mfa.extensions;

import org.jahia.modules.graphql.provider.dxm.DataFetchingException;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRSessionFactory;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.usermanager.JahiaUser;
import org.jahia.services.usermanager.JahiaUserManagerService;
import org.junit.Test;
import org.mockito.MockedStatic;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The subject rule behind {@link MfaAdminAccess#requireAdminForUser}: who a caller may act upon with
 * an admin-recovery operation that runs on a system session (clearing a second factor), and WHICH
 * account that operation then touches.
 * <p>
 * Two properties are pinned here, both learned the hard way:
 * <ul>
 *   <li><b>the site never authorizes the subject.</b> Site administration used to be enough, so the
 *       administrator of any minor site could strip {@code root}'s MFA. It was then narrowed to "the
 *       site's OWN users" &mdash; a branch that cannot succeed, because every account able to hold
 *       MFA in this module lives in the global {@code /users/} tree. Server administration is
 *       required for every subject;</li>
 *   <li><b>one resolution.</b> Authorization resolves the subject with
 *       {@code JahiaUserManagerService.lookupUser(userId)} &mdash; the same global lookup every
 *       store method performs &mdash; and hands the resolved node back. Authorizing on the
 *       site-aware lookup while writing through the global one let a site-scoped user pass the gate
 *       and then hit nothing: a green {@code true} on an account that was never touched.</li>
 * </ul>
 */
public class MfaAdminAccessTest {

    private static final String SITE = "minorSite";
    private static final String PREFIX = "factor.test.";

    @Test
    public void siteAdministrationAloneNeverAuthorizesASubject() {
        try (MockedStatic<JCRSessionFactory> sessions = caller(false);
             MockedStatic<JahiaUserManagerService> users = statics(mock(JahiaUserManagerService.class))) {

            assertDenied("permission_denied", () -> MfaAdminAccess.requireAdminForUser("root", SITE, PREFIX));
        }
    }

    @Test
    public void theSubjectIsResolvedWithTheGlobalLookupTheStoresUse_andNoOther() {
        // The divergence that produced the silent success: lookupUser(userId, siteKey) also searches
        // /sites/<key>/users/, so it could authorize an account that lookupUser(userId) - the
        // resolution EVERY store method performs - can never find. The gate must consult the store's
        // lookup, and only that one; a subject it does not resolve is an error, not a quiet no-op.
        JahiaUserManagerService service = mock(JahiaUserManagerService.class);

        try (MockedStatic<JCRSessionFactory> sessions = caller(true);
             MockedStatic<JahiaUserManagerService> users = statics(service)) {

            assertDenied("user_not_found", () -> MfaAdminAccess.requireAdminForUser("bob", SITE, PREFIX));
        }

        verify(service).lookupUser("bob");
        verify(service, never()).lookupUser(anyString(), anyString());
    }

    @Test
    public void anUnknownUserIsReportedRatherThanSilentlyAccepted() {
        try (MockedStatic<JCRSessionFactory> sessions = caller(true);
             MockedStatic<JahiaUserManagerService> users = statics(mock(JahiaUserManagerService.class))) {

            assertDenied("user_not_found", () -> MfaAdminAccess.requireAdminForUser("typo", SITE, PREFIX));
        }
    }

    @Test
    public void existenceIsNotProbeableWithoutTheRightToAct() {
        // Rights are checked before existence: otherwise a site administrator - who may not reset
        // anyone - could tell existing platform accounts apart from typos, one call at a time.
        try (MockedStatic<JCRSessionFactory> sessions = caller(false);
             MockedStatic<JahiaUserManagerService> users = statics(mock(JahiaUserManagerService.class))) {

            assertDenied("permission_denied", () -> MfaAdminAccess.requireAdminForUser("typo", SITE, PREFIX));
        }
    }

    // --- requireServerAdmin (the platform-wide reads) -----------------------------------------

    @Test
    public void requireServerAdmin_rejectsAMereSiteAdministrator() {
        try (MockedStatic<JCRSessionFactory> sessions = caller(false)) {
            assertDenied("permission_denied", () -> MfaAdminAccess.requireServerAdmin(PREFIX));
        }
    }

    @Test
    public void requireServerAdmin_acceptsAServerAdministrator() {
        try (MockedStatic<JCRSessionFactory> sessions = caller(true)) {
            MfaAdminAccess.requireServerAdmin(PREFIX); // no exception
        }
    }

    @Test
    public void requireServerAdmin_rejectsAnUnauthenticatedCaller() {
        JCRSessionFactory factory = mock(JCRSessionFactory.class);
        when(factory.getCurrentUser()).thenReturn(null);
        try (MockedStatic<JCRSessionFactory> sessions = mockStatic(JCRSessionFactory.class)) {
            sessions.when(JCRSessionFactory::getInstance).thenReturn(factory);
            assertDenied("not_authenticated", () -> MfaAdminAccess.requireServerAdmin(PREFIX));
        }
    }

    // --- fixtures ------------------------------------------------------------------------------

    private static void assertDenied(String expectedCode, Runnable call) {
        try {
            call.run();
            fail("expected " + PREFIX + expectedCode);
        } catch (DataFetchingException e) {
            assertEquals(PREFIX + expectedCode, e.getMessage());
        }
    }

    /**
     * The caller: a non-root user holding {@code siteAdminAccess} on {@code /sites/minorSite}, and
     * {@code administrationAccess} on the repository root only when {@code serverAdmin} is true.
     */
    private static MockedStatic<JCRSessionFactory> caller(boolean serverAdmin) {
        try {
            JahiaUser user = mock(JahiaUser.class);
            when(user.getName()).thenReturn("sitealice");
            when(user.isRoot()).thenReturn(false);

            JCRNodeWrapper siteNode = mock(JCRNodeWrapper.class);
            when(siteNode.hasPermission(MfaAdminAccess.SITE_ADMIN_PERMISSION)).thenReturn(true);
            JCRNodeWrapper rootNode = mock(JCRNodeWrapper.class);
            when(rootNode.hasPermission(MfaAdminAccess.SERVER_ADMIN_PERMISSION)).thenReturn(serverAdmin);

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
        } catch (Exception e) {
            throw new IllegalStateException(e); // mock setup only; JCR signatures declare checked types
        }
    }

    /**
     * The resolved-subject side of the gate (a {@code JCRUserNode} handed back and carried into the
     * write) is exercised end-to-end in the factor bundles, whose test classpath can mock that class
     * &mdash; {@code TotpResetUserMfaAuthorizationTest} and {@code WebAuthnResetUserAuthorizationTest}.
     * Here the subject is always absent, which keeps these cases free of a Jahia node fixture.
     */
    private static MockedStatic<JahiaUserManagerService> statics(JahiaUserManagerService service) {
        MockedStatic<JahiaUserManagerService> statics = mockStatic(JahiaUserManagerService.class);
        statics.when(JahiaUserManagerService::getInstance).thenReturn(service);
        return statics;
    }
}
