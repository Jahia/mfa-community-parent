package org.jahia.modules.upa.mfa.webauthn;

import org.jahia.modules.upa.mfa.MfaException;
import org.jahia.modules.upa.mfa.MfaSessionContext;
import org.jahia.modules.upa.mfa.VerificationContext;
import org.junit.Before;
import org.junit.Test;

import javax.jcr.RepositoryException;
import java.util.Collections;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * U10 (provider-level clone-detection integrity + ownership post-check): while
 * {@code WebAuthnCredentialStore.nextSignCount} monotonicity is covered by
 * {@link WebAuthnCredentialStoreTest} (F26), the provider's {@link WebAuthnFactorProvider#verify}
 * adds two defense-in-depth guards on top of the yubico ceremony:
 * <ul>
 *   <li>the asserted credential MUST be owned by the session user ({@code isCredentialOwnedBy});</li>
 *   <li>if the new signature counter cannot be persisted ({@code updateOnAssertion} throws
 *       {@link RepositoryException}) the login is REFUSED, so a clone-detection gap is never left
 *       silently open.</li>
 * </ul>
 * Driven with fakes (the codebase's subclass-fake pattern; no Mockito), building the package-private
 * {@code AssertionOutcome} directly.
 */
public class WebAuthnFactorProviderVerifyTest {

    private static final String USER = "alice";
    private static final String SITE = "siteA";
    private static final String CRED_ID = "credABC";

    private WebAuthnFactorProvider provider;
    private FakeService service;
    private FakeStore store;
    private RecordingAuditLog audit;

    @Before
    public void setUp() {
        provider = new WebAuthnFactorProvider();
        service = new FakeService();
        store = new FakeStore();
        audit = new RecordingAuditLog();
        provider.setWebAuthnService(service);
        provider.setCredentialStore(store);
        provider.setAuditLog(audit);
    }

    @Test
    public void validAssertion_ownedAndPersisted_authenticatesAndUpdatesCounter() throws Exception {
        service.outcome = new WebAuthnService.AssertionOutcome(true, CRED_ID, 42L);
        store.owned = true;

        assertTrue("a valid, owned, persistable assertion authenticates", provider.verify(ctx("{resp}")));
        assertTrue("the new sign counter must be persisted on success", store.updateCalled.get());
        assertEquals("success", audit.lastOutcome);
    }

    @Test
    public void validAssertion_credentialNotOwnedBySessionUser_isRejected() throws Exception {
        // The yubico ceremony passed, but the matched credential belongs to another account.
        service.outcome = new WebAuthnService.AssertionOutcome(true, CRED_ID, 42L);
        store.owned = false;

        assertFalse("an assertion for an unowned credential must be rejected", provider.verify(ctx("{resp}")));
        assertFalse("the counter must NOT be updated for an unowned credential", store.updateCalled.get());
        assertEquals("failure", audit.lastOutcome);
    }

    @Test
    public void validAssertion_counterCannotBePersisted_refusesLogin() throws Exception {
        // Valid + owned, but the store cannot persist the advanced counter -> refuse to preserve
        // clone-detection integrity (do NOT let the login through with a non-advanced counter).
        service.outcome = new WebAuthnService.AssertionOutcome(true, CRED_ID, 99L);
        store.owned = true;
        store.throwOnUpdate = true;

        assertFalse("a valid assertion whose counter can't be persisted must be refused",
                provider.verify(ctx("{resp}")));
        assertEquals("failure", audit.lastOutcome);
    }

    @Test
    public void unsuccessfulCeremony_isRejected() throws Exception {
        service.outcome = new WebAuthnService.AssertionOutcome(false, null, 0L);
        store.owned = true;

        assertFalse("a failed yubico ceremony must be rejected", provider.verify(ctx("{resp}")));
        assertFalse(store.updateCalled.get());
    }

    @Test
    public void blankVerificationData_throwsDataRequired() {
        service.outcome = new WebAuthnService.AssertionOutcome(true, CRED_ID, 1L);
        store.owned = true;
        try {
            provider.verify(ctx("   "));
            fail("blank verification data must be refused");
        } catch (MfaException e) {
            assertEquals(WebAuthnFactorProvider.ERROR_VERIFICATION_DATA_REQUIRED, e.getCode());
        }
    }

    // --- helpers --------------------------------------------------------------------------------

    private static VerificationContext ctx(String verificationData) {
        MfaSessionContext sessionContext = new MfaSessionContext(
                USER, Locale.ENGLISH, SITE, false, Collections.singletonList("webauthn"));
        WebAuthnPreparationResult prep = new WebAuthnPreparationResult(false, "{request}", "{clientOptions}");
        return new VerificationContext(sessionContext, prep, verificationData, null, null);
    }

    private static class FakeService extends WebAuthnService {
        AssertionOutcome outcome;

        @Override
        public AssertionOutcome finishAssertion(String requestJson, String responseJson) {
            return outcome;
        }
    }

    private static class FakeStore extends WebAuthnCredentialStore {
        boolean owned;
        boolean throwOnUpdate;
        final AtomicBoolean updateCalled = new AtomicBoolean(false);

        @Override
        public boolean isCredentialOwnedBy(String userId, String credentialIdB64) {
            return owned;
        }

        @Override
        public void updateOnAssertion(String userId, String credentialIdB64, long newSignCount)
                throws RepositoryException {
            if (throwOnUpdate) {
                throw new RepositoryException("simulated JCR write failure");
            }
            updateCalled.set(true);
        }
    }

    private static class RecordingAuditLog extends WebAuthnAuditLog {
        String lastOutcome;

        @Override
        public void recordEvent(String eventType, String outcome, String userId, String siteKey, String detail) {
            this.lastOutcome = outcome;
        }
    }
}
