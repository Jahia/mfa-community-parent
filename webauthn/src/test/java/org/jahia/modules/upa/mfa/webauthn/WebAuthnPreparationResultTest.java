package org.jahia.modules.upa.mfa.webauthn;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * The WebAuthn login preparation result is stored in the MFA / HTTP session between the
 * {@code prepare} and {@code verify} calls, so it MUST be Java-serializable and round-trip its
 * ceremony JSON unchanged (the {@code requestJson} is what {@code finishAssertion} needs).
 */
public class WebAuthnPreparationResultTest {

    @Test
    public void skippedMarkerCarriesNoCeremonyState() {
        WebAuthnPreparationResult skipped = new WebAuthnPreparationResult(true);
        assertTrue(skipped.isSkipped());
        assertNull(skipped.getRequestJson());
        assertNull(skipped.getClientOptionsJson());
    }

    @Test
    public void carriesRequestAndClientOptions() {
        WebAuthnPreparationResult r = new WebAuthnPreparationResult(false, "{\"req\":1}", "{\"opts\":2}");
        assertFalse(r.isSkipped());
        assertEquals("{\"req\":1}", r.getRequestJson());
        assertEquals("{\"opts\":2}", r.getClientOptionsJson());
    }

    @Test
    public void survivesJavaSerialization() throws Exception {
        WebAuthnPreparationResult original =
                new WebAuthnPreparationResult(false, "{\"challenge\":\"abc\"}", "{\"publicKey\":{}}");

        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
            out.writeObject(original);
        }
        WebAuthnPreparationResult restored;
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
            restored = (WebAuthnPreparationResult) in.readObject();
        }

        assertFalse(restored.isSkipped());
        assertEquals(original.getRequestJson(), restored.getRequestJson());
        assertEquals(original.getClientOptionsJson(), restored.getClientOptionsJson());
    }
}
