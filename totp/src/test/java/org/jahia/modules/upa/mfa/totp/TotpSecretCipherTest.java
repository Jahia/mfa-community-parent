package org.jahia.modules.upa.mfa.totp;

import org.junit.Before;
import org.junit.Test;

import java.util.Base64;
import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * {@link TotpSecretCipher} AES-GCM round-trip and envelope handling. Activated with a fixed
 * Base64 256-bit key (the operator-supplied {@code secret.encryption.key}) so the test never
 * touches the filesystem key file.
 */
public class TotpSecretCipherTest {

    /** A deterministic 256-bit AES key, Base64-encoded (32 zero bytes - fine for a unit test). */
    private static final String FIXED_KEY_B64 = Base64.getEncoder().encodeToString(new byte[32]);

    private TotpSecretCipher cipher;

    @Before
    public void setUp() {
        cipher = new TotpSecretCipher();
        cipher.activate(Collections.singletonMap("secret.encryption.key", FIXED_KEY_B64));
    }

    @Test
    public void encryptThenDecrypt_roundTrips() {
        String plaintext = "JBSWY3DPEHPK3PXP";
        String encrypted = cipher.encrypt(plaintext);
        assertNotEquals("ciphertext must differ from plaintext", plaintext, encrypted);
        assertEquals(plaintext, cipher.decrypt(encrypted));
    }

    @Test
    public void isEncrypted_v1Envelope_isTrue() {
        assertTrue(cipher.isEncrypted(cipher.encrypt("JBSWY3DPEHPK3PXP")));
    }

    @Test
    public void isEncrypted_plaintext_isFalse() {
        assertFalse(cipher.isEncrypted("JBSWY3DPEHPK3PXP"));
    }

    @Test
    public void decrypt_nonV1Value_passesThroughUnchanged() {
        // Legacy plaintext (no v1: prefix) is returned as-is for backward compatibility.
        String legacy = "JBSWY3DPEHPK3PXP";
        assertEquals(legacy, cipher.decrypt(legacy));
    }

    @Test
    public void decrypt_tamperedCiphertext_throws() {
        String encrypted = cipher.encrypt("JBSWY3DPEHPK3PXP");
        // Decode the ciphertext segment, flip one byte, re-encode - guarantees a GCM tag mismatch
        // (a deterministic corruption, unlike flipping a base64 character in place).
        String[] parts = encrypted.split(":", 3);
        Base64.Decoder dec = Base64.getDecoder();
        Base64.Encoder enc = Base64.getEncoder();
        byte[] ciphertext = dec.decode(parts[2]);
        ciphertext[0] ^= 0x01;
        String tampered = parts[0] + ":" + parts[1] + ":" + enc.encodeToString(ciphertext);
        try {
            cipher.decrypt(tampered);
            fail("a tampered ciphertext must not decrypt");
        } catch (IllegalStateException expected) {
            // expected
        }
    }

    @Test
    public void decrypt_twoPartEnvelope_throws() {
        // A v1 envelope must carry exactly iv:ciphertext (3 colon-separated parts with the prefix).
        try {
            cipher.decrypt(TotpSecretCipher.PREFIX_V1 + "onlyonepart");
            fail("a malformed 2-part envelope must throw");
        } catch (IllegalStateException expected) {
            // expected
        }
    }
}
