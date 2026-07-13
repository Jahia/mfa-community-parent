package org.jahia.modules.upa.mfa.totp;

import org.jahia.services.content.JCRCallback;
import org.jahia.services.content.JCRPropertyWrapper;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.content.JCRTemplate;
import org.jahia.services.content.decorator.JCRUserNode;
import org.jahia.services.usermanager.JahiaUserManagerService;
import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.invocation.Invocation;

import java.util.Collections;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.mockingDetails;
import static org.mockito.Mockito.when;

/**
 * JCR-bound {@link TotpUserStore} behaviours that the pure-logic suites cannot reach:
 * <ul>
 *   <li>U3 — {@code verifyAndConsumeTotp} transparently RE-ENCRYPTS a legacy plaintext secret on the
 *       next successful verify (migration path);</li>
 *   <li>D8 — grace is RE-GRANTED after an admin reset: {@code clearGrace} zeroes
 *       {@code graceStartedAt}, and the next {@code getOrStartGraceMillis} re-initialises a fresh
 *       window rather than treating the user as permanently past grace.</li>
 * </ul>
 * The store hardcodes {@code JCRTemplate.getInstance()} and works over concrete
 * {@code JCRUserNode}/{@code JCRPropertyWrapper}; mockito-inline mocks the static + those types.
 */
public class TotpUserStoreJcrTest {

    private static final String USER = "alice";
    private static final String FIXED_KEY_B64 = java.util.Base64.getEncoder().encodeToString(new byte[32]);

    // --- U3: lazy re-encryption of a legacy plaintext secret -----------------------------------

    @Test
    public void verifyAndConsumeTotp_reEncryptsLegacyPlaintextSecretOnSuccess() throws Exception {
        TotpSecretCipher cipher = new TotpSecretCipher();
        cipher.activate(Collections.singletonMap("secret.encryption.key", FIXED_KEY_B64));
        TotpService totpService = new TotpService();

        // A legacy secret is stored as bare Base32 (no v1: envelope) — cipher.decrypt passes it through.
        String legacySecret = totpService.toBase32(totpService.generateSecret());
        assertTrue("precondition: the legacy secret is NOT encrypted", !cipher.isEncrypted(legacySecret));

        long now = 1_000_000_000L;
        long counter = now / TotpService.TIME_STEP_SECONDS;
        String validCode = totpService.generateCode(totpService.fromBase32(legacySecret), counter);

        // Build the property mocks BEFORE stubbing user.getProperty (no nested when()).
        JCRPropertyWrapper enrolledProp = boolProp(true);
        JCRPropertyWrapper secretProp = stringProp(legacySecret);
        JCRPropertyWrapper counterProp = longProp(0L);

        JCRUserNode user = mock(JCRUserNode.class);
        when(user.isNodeType(TotpUserStore.MIXIN_USER_SETTINGS)).thenReturn(true);
        when(user.hasProperty(TotpUserStore.PROP_ENROLLED)).thenReturn(true);
        when(user.getProperty(TotpUserStore.PROP_ENROLLED)).thenReturn(enrolledProp);
        when(user.hasProperty(TotpUserStore.PROP_SECRET)).thenReturn(true);
        when(user.getProperty(TotpUserStore.PROP_SECRET)).thenReturn(secretProp);
        when(user.hasProperty(TotpUserStore.PROP_LAST_USED_COUNTER)).thenReturn(true);
        when(user.getProperty(TotpUserStore.PROP_LAST_USED_COUNTER)).thenReturn(counterProp);

        TotpUserStore store = storeWith(user, cipher);

        Optional<Long> matched;
        try (MockedStatic<JCRTemplate> statics = staticTemplate(user)) {
            matched = store.verifyAndConsumeTotp(USER, totpService, validCode, now, TotpService.DRIFT_WINDOWS);
        }

        assertTrue("a valid code against the legacy secret must verify", matched.isPresent());
        // The matched counter is persisted (replay protection) AND the secret is re-written encrypted.
        String reWrittenSecret = lastStringValueSetFor(user, TotpUserStore.PROP_SECRET);
        assertTrue("the legacy secret must be transparently re-encrypted (v1 envelope) on success",
                cipher.isEncrypted(reWrittenSecret));
        assertEquals("the re-encrypted secret must decrypt back to the original",
                legacySecret, cipher.decrypt(reWrittenSecret));
    }

    // --- D8: grace re-granted after an admin reset ----------------------------------------------

    @Test
    public void clearGraceThenGetOrStart_reGrantsAFreshGraceWindow() throws Exception {
        long tenDaysAgo = System.currentTimeMillis() - 10L * 24 * 60 * 60 * 1000;
        long[] graceStartedAt = {tenDaysAgo};

        JCRUserNode user = mock(JCRUserNode.class);
        when(user.isNodeType(TotpUserStore.MIXIN_GRACE_TRACKING)).thenReturn(true);
        when(user.hasProperty(TotpUserStore.PROP_GRACE_STARTED_AT)).thenReturn(true);
        JCRPropertyWrapper graceProp = mock(JCRPropertyWrapper.class);
        when(graceProp.getLong()).thenAnswer(inv -> graceStartedAt[0]);
        when(user.getProperty(TotpUserStore.PROP_GRACE_STARTED_AT)).thenReturn(graceProp);
        doAnswer(inv -> {
            graceStartedAt[0] = inv.getArgument(1);
            return null;
        }).when(user).setProperty(eq(TotpUserStore.PROP_GRACE_STARTED_AT), anyLong());

        TotpUserStore store = storeWith(user, null);

        long now = System.currentTimeMillis();
        try (MockedStatic<JCRTemplate> statics = staticTemplate(user)) {
            // Admin reset zeroes the grace marker...
            store.clearGrace(USER);
            assertEquals("clearGrace must zero graceStartedAt", 0L, graceStartedAt[0]);

            // ...and the next enforced prompt re-initialises a FRESH window (not "permanently past grace").
            long grace = store.getOrStartGraceMillis(USER, now);
            assertEquals("a fresh grace window must be re-granted after reset", now, grace);
            assertEquals("the fresh window start is persisted", now, graceStartedAt[0]);
        }
    }

    // --- helpers --------------------------------------------------------------------------------

    private static TotpUserStore storeWith(JCRUserNode user, TotpSecretCipher cipher) {
        TotpUserStore store = new TotpUserStore();
        JahiaUserManagerService userManager = mock(JahiaUserManagerService.class);
        when(userManager.lookupUser(eq(USER), any(JCRSessionWrapper.class))).thenReturn(user);
        store.setUserManagerService(userManager);
        if (cipher != null) {
            store.setSecretCipher(cipher);
        }
        return store;
    }

    private static MockedStatic<JCRTemplate> staticTemplate(JCRUserNode user) throws Exception {
        JCRSessionWrapper session = mock(JCRSessionWrapper.class);
        JCRTemplate template = mock(JCRTemplate.class);
        when(template.doExecuteWithSystemSession(any())).thenAnswer(inv ->
                inv.getArgument(0, JCRCallback.class).doInJCR(session));
        MockedStatic<JCRTemplate> statics = mockStatic(JCRTemplate.class);
        statics.when(JCRTemplate::getInstance).thenReturn(template);
        return statics;
    }

    private static JCRPropertyWrapper boolProp(boolean v) throws Exception {
        JCRPropertyWrapper p = mock(JCRPropertyWrapper.class);
        when(p.getBoolean()).thenReturn(v);
        return p;
    }

    private static JCRPropertyWrapper stringProp(String v) throws Exception {
        JCRPropertyWrapper p = mock(JCRPropertyWrapper.class);
        when(p.getString()).thenReturn(v);
        return p;
    }

    private static JCRPropertyWrapper longProp(long v) throws Exception {
        JCRPropertyWrapper p = mock(JCRPropertyWrapper.class);
        when(p.getLong()).thenReturn(v);
        return p;
    }

    /** The last String value written via {@code setProperty(name, value)} on {@code user}. */
    private static String lastStringValueSetFor(JCRUserNode user, String propertyName) {
        String value = null;
        for (Invocation inv : mockingDetails(user).getInvocations()) {
            if ("setProperty".equals(inv.getMethod().getName())
                    && inv.getArguments().length >= 2
                    && propertyName.equals(inv.getArguments()[0])
                    && inv.getArguments()[1] instanceof String) {
                value = (String) inv.getArguments()[1];
            }
        }
        return value;
    }
}
