package org.jahia.modules.upa.mfa.extensions;

import org.junit.Test;

import static org.jahia.modules.upa.mfa.extensions.MfaAdminAccess.isScopedToSite;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * The subject-scoping rule behind {@link MfaAdminAccess#requireSiteAdminForUser}: which users a
 * SITE administrator may act upon with an admin-recovery operation that runs on a system session
 * (clearing a second factor). Only the site's OWN users ({@code /sites/<siteKey>/users/...}) are in
 * scope; a global user ({@code /users/...}) belongs to the platform, not to one site, so the same
 * operation on it requires server administration. Without that distinction the administrator of any
 * minor site could strip {@code root}'s MFA.
 */
public class MfaAdminAccessTest {

    @Test
    public void aSitesOwnUserIsInScopeOfThatSite() {
        assertTrue(isScopedToSite("/sites/mySite/users/bo/b/bob", "mySite"));
    }

    @Test
    public void aGlobalUserIsNeverInScopeOfASite() {
        assertFalse("root is a platform user, not a site user",
                isScopedToSite("/users/ro/ot/root", "mySite"));
        assertFalse(isScopedToSite("/users/jd/oe/jdoe", "mySite"));
    }

    @Test
    public void anotherSitesUserIsNotInScope() {
        assertFalse(isScopedToSite("/sites/otherSite/users/bo/b/bob", "mySite"));
    }

    @Test
    public void aSiteKeyThatIsMerelyAPrefixDoesNotMatch() {
        // '/sites/mySiteEvil/users/...' must not be accepted as '/sites/mySite/...'.
        assertFalse(isScopedToSite("/sites/mySiteEvil/users/bo/b/bob", "mySite"));
    }

    @Test
    public void theSiteNodeItselfIsNotAUserInScope() {
        assertFalse(isScopedToSite("/sites/mySite", "mySite"));
        assertFalse(isScopedToSite("/sites/mySite/users", "mySite"));
    }

    @Test
    public void blankInputsAreNeverInScope() {
        assertFalse(isScopedToSite(null, "mySite"));
        assertFalse(isScopedToSite("", "mySite"));
        assertFalse(isScopedToSite("/sites/mySite/users/bo/b/bob", null));
        assertFalse(isScopedToSite("/sites/mySite/users/bo/b/bob", " "));
    }
}
