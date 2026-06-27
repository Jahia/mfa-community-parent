package org.jahia.modules.upa.mfa.extensions.internal;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * The static markers of {@link EmailCodeFactorAdapter}, the {@code MfaSiteProvider} that speaks
 * for UPA's built-in {@code email_code} factor. These drive the cross-factor infrastructure: the
 * factor type it claims, that it is a FOREIGN factor (UPA's provider cannot skip itself, so the
 * drain must release it), and that it is NOT inline-enrollable (the sign-in flow cannot add an
 * email address to a profile).
 */
public class EmailCodeFactorAdapterTest {

    private EmailCodeFactorAdapter adapter;

    @Before
    public void setUp() {
        adapter = new EmailCodeFactorAdapter();
    }

    @Test
    public void factorType_isEmailCode() {
        assertEquals("email_code", adapter.getFactorType());
    }

    @Test
    public void isForeignFactor_isTrue() {
        assertTrue(adapter.isForeignFactor());
    }

    @Test
    public void isInlineEnrollable_isFalse() {
        assertFalse(adapter.isInlineEnrollable());
    }
}
