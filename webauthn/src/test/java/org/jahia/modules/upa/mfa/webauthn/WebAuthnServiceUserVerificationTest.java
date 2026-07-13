package org.jahia.modules.upa.mfa.webauthn;

import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Optional;
import java.util.Set;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * U9: WebAuthn user verification is {@code PREFERRED}, not {@code REQUIRED}, for BOTH registration
 * and assertion — the factor is possession-bound but does not force a PIN/biometric. This is a
 * deliberate design choice for a second factor; the test locks it against a silent downgrade to
 * {@code DISCOURAGED} (which would drop UV entirely) or an unintended change of intent.
 * <p>
 * Uses a real {@link WebAuthnService} + real {@link WebAuthnConfig} over {@code localhost} with a
 * fake (empty) credential repository, and inspects the emitted client-options JSON.
 */
public class WebAuthnServiceUserVerificationTest {

    private WebAuthnService service;

    @Before
    public void setUp() {
        WebAuthnConfig config = new WebAuthnConfig();
        config.activate(new HashMap<>()); // defaults: rpId=localhost
        service = new WebAuthnService();
        service.setConfig(config);
        service.setCredentialStore(new EmptyStore());
    }

    @Test
    public void assertionOptions_useUserVerificationPreferred() throws Exception {
        WebAuthnService.AssertionCeremony ceremony = service.startAssertion("alice");
        String clientOptions = ceremony.getClientOptionsJson();
        assertTrue("assertion options must request userVerification=preferred, got: " + clientOptions,
                clientOptions.contains("\"userVerification\":\"preferred\""));
        assertFalse("must never silently downgrade to discouraged",
                clientOptions.contains("\"userVerification\":\"discouraged\""));
    }

    @Test
    public void registrationOptions_useUserVerificationPreferred() throws Exception {
        ByteArray userHandle = new ByteArray("alice-user-handle".getBytes(StandardCharsets.UTF_8));
        WebAuthnService.RegistrationCeremony ceremony = service.startRegistration("alice", "Alice", userHandle);
        String clientOptions = ceremony.getClientOptionsJson();
        assertTrue("registration options must request userVerification=preferred, got: " + clientOptions,
                clientOptions.contains("\"userVerification\":\"preferred\""));
        assertFalse("must never silently downgrade to discouraged",
                clientOptions.contains("\"userVerification\":\"discouraged\""));
    }

    /** A credential repository with no credentials — enough to start the ceremonies. */
    private static class EmptyStore extends WebAuthnCredentialStore {
        @Override
        public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
            return Collections.emptySet();
        }

        @Override
        public Optional<ByteArray> getUserHandleForUsername(String username) {
            return Optional.of(new ByteArray(username.getBytes(StandardCharsets.UTF_8)));
        }
    }
}
