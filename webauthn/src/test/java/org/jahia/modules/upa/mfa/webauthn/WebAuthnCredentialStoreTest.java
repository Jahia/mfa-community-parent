package org.jahia.modules.upa.mfa.webauthn;

import org.junit.Test;

import static org.jahia.modules.upa.mfa.webauthn.WebAuthnCredentialStore.nextSignCount;
import static org.junit.Assert.assertEquals;

/**
 * The pure monotonic-advance rule for the persisted WebAuthn signature counter
 * ({@link WebAuthnCredentialStore#nextSignCount}): the stored counter only ever advances; a
 * regressing or equal observed value (a possible cloned authenticator, or one that keeps no
 * counter) leaves the stored value untouched.
 */
public class WebAuthnCredentialStoreTest {

    @Test
    public void advancesWhenObservedIsGreater() {
        assertEquals(7L, nextSignCount(5L, 7L));
    }

    @Test
    public void keepsCurrentWhenObservedEquals() {
        assertEquals(5L, nextSignCount(5L, 5L));
    }

    @Test
    public void keepsCurrentWhenObservedRegresses() {
        // A counter going backwards signals a cloned authenticator — never roll the stored value back.
        assertEquals(9L, nextSignCount(9L, 3L));
    }

    @Test
    public void keepsCurrentWhenObservedIsZero() {
        // 0 means the authenticator keeps no counter; the stored value stands.
        assertEquals(4L, nextSignCount(4L, 0L));
    }

    @Test
    public void advancesFromZeroBaseline() {
        assertEquals(1L, nextSignCount(0L, 1L));
    }
}
