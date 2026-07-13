package org.jahia.modules.upa.mfa.webauthn;

import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * F25 — WebAuthn login assertion validation, the highest-value security-coverage gap. Drives the
 * REAL yubico {@code finishAssertion} ceremony through {@link WebAuthnService} with a fixed EC
 * P-256 key pair and a hand-built, correctly-signed authenticator assertion, then flips origin /
 * RP-ID / challenge one at a time and asserts each is rejected.
 * <p>
 * This is the unit half of F25. The E2E half (a Chrome CDP virtual authenticator driving a live
 * {@code prepare -> get() -> verify}) is written as a Cypress spec and runs in Stage 6; the
 * provider-level ownership / refuse-on-persist guards are covered by
 * {@link WebAuthnFactorProviderVerifyTest} (U10).
 */
public class WebAuthnAssertionCeremonyTest {

    private static final String RP_ID = "localhost";
    private static final String GOOD_ORIGIN = "https://localhost";
    private static final String USERNAME = "alice";

    private KeyPair keyPair;
    private ByteArray credentialId;
    private ByteArray userHandle;
    private ByteArray coseKey;
    private WebAuthnService service;

    @Before
    public void setUp() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        keyPair = kpg.generateKeyPair();
        credentialId = new ByteArray("cred-alice-fixed-id".getBytes(StandardCharsets.UTF_8));
        userHandle = new ByteArray("user-handle-alice".getBytes(StandardCharsets.UTF_8));
        coseKey = coseEs256((ECPublicKey) keyPair.getPublic());

        WebAuthnConfig config = new WebAuthnConfig();
        config.activate(new HashMap<>()); // rpId=localhost → origins {https://localhost, http://localhost}
        service = new WebAuthnService();
        service.setConfig(config);
        service.setCredentialStore(new FixedCredentialStore());
    }

    @Test
    public void validAssertion_authenticatesAndReportsCredentialAndCounter() throws Exception {
        String requestJson = service.startAssertion(USERNAME).getRequestJson();
        String responseJson = signedAssertion(requestJson, GOOD_ORIGIN, RP_ID, challengeOf(requestJson), 7L);

        WebAuthnService.AssertionOutcome outcome = service.finishAssertion(requestJson, responseJson);

        assertTrue("a correctly-signed, origin/rpId/challenge-matching assertion must succeed",
                outcome.isSuccess());
        assertEquals("the asserted credential id must be reported back",
                credentialId.getBase64Url(), outcome.getCredentialIdB64());
        assertEquals("the authenticator's new signature counter must be surfaced",
                7L, outcome.getNewSignCount());
    }

    @Test
    public void wrongOrigin_isRejected() throws Exception {
        String requestJson = service.startAssertion(USERNAME).getRequestJson();
        String responseJson = signedAssertion(requestJson, "https://evil.example.com", RP_ID,
                challengeOf(requestJson), 7L);
        assertFalse("an assertion whose clientData origin != configured origin must be rejected",
                service.finishAssertion(requestJson, responseJson).isSuccess());
    }

    @Test
    public void wrongRpId_isRejected() throws Exception {
        String requestJson = service.startAssertion(USERNAME).getRequestJson();
        // authenticatorData carries rpIdHash = SHA-256("evil.example") instead of the configured rpId.
        String responseJson = signedAssertion(requestJson, GOOD_ORIGIN, "evil.example",
                challengeOf(requestJson), 7L);
        assertFalse("an assertion whose rpIdHash != SHA-256(configured rpId) must be rejected",
                service.finishAssertion(requestJson, responseJson).isSuccess());
    }

    @Test
    public void staleChallenge_isRejected() throws Exception {
        String requestJson = service.startAssertion(USERNAME).getRequestJson();
        ByteArray staleChallenge = new ByteArray("a-different-stale-challenge-value".getBytes(StandardCharsets.UTF_8));
        String responseJson = signedAssertion(requestJson, GOOD_ORIGIN, RP_ID, staleChallenge, 7L);
        assertFalse("an assertion echoing a challenge != the server's must be rejected",
                service.finishAssertion(requestJson, responseJson).isSuccess());
    }

    // --- assertion crafting ---------------------------------------------------------------------

    private static ByteArray challengeOf(String requestJson) throws Exception {
        return AssertionRequest.fromJson(requestJson)
                .getPublicKeyCredentialRequestOptions().getChallenge();
    }

    /**
     * Build a WebAuthn assertion response JSON signed by {@link #keyPair}'s private key over
     * {@code authenticatorData || SHA-256(clientDataJSON)}, as a real authenticator would.
     */
    private String signedAssertion(String requestJson, String origin, String rpId, ByteArray challenge,
                                   long signCount) throws Exception {
        String clientDataJson = "{\"type\":\"webauthn.get\",\"challenge\":\"" + challenge.getBase64Url()
                + "\",\"origin\":\"" + origin + "\",\"crossOrigin\":false}";
        byte[] clientData = clientDataJson.getBytes(StandardCharsets.UTF_8);

        byte[] authenticatorData = authenticatorData(rpId, signCount);
        byte[] clientDataHash = sha256(clientData);

        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign((PrivateKey) keyPair.getPrivate());
        ecdsa.update(authenticatorData);
        ecdsa.update(clientDataHash);
        byte[] signature = ecdsa.sign(); // ASN.1 DER, as WebAuthn expects

        return "{"
                + "\"type\":\"public-key\","
                + "\"id\":\"" + credentialId.getBase64Url() + "\","
                + "\"rawId\":\"" + credentialId.getBase64Url() + "\","
                + "\"response\":{"
                + "\"authenticatorData\":\"" + new ByteArray(authenticatorData).getBase64Url() + "\","
                + "\"clientDataJSON\":\"" + new ByteArray(clientData).getBase64Url() + "\","
                + "\"signature\":\"" + new ByteArray(signature).getBase64Url() + "\","
                + "\"userHandle\":\"" + userHandle.getBase64Url() + "\""
                + "},"
                + "\"clientExtensionResults\":{}"
                + "}";
    }

    /** rpIdHash(32) || flags(0x01 UP) || signCount(4, big-endian). */
    private static byte[] authenticatorData(String rpId, long signCount) throws Exception {
        byte[] rpIdHash = sha256(rpId.getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(rpIdHash);
        out.write(0x01); // User Present
        out.write((int) ((signCount >> 24) & 0xFF));
        out.write((int) ((signCount >> 16) & 0xFF));
        out.write((int) ((signCount >> 8) & 0xFF));
        out.write((int) (signCount & 0xFF));
        return out.toByteArray();
    }

    /** Canonical COSE_Key for an ES256 (EC2 / P-256) public key. */
    private static ByteArray coseEs256(ECPublicKey key) {
        byte[] x = fixed32(key.getW().getAffineX().toByteArray());
        byte[] y = fixed32(key.getW().getAffineY().toByteArray());
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xA5);              // map(5)
        out.write(0x01); out.write(0x02);   // 1 (kty) : 2 (EC2)
        out.write(0x03); out.write(0x26);   // 3 (alg) : -7 (ES256)
        out.write(0x20); out.write(0x01);   // -1 (crv): 1 (P-256)
        out.write(0x21); out.write(0x58); out.write(0x20); out.write(x, 0, 32); // -2 (x): bstr(32)
        out.write(0x22); out.write(0x58); out.write(0x20); out.write(y, 0, 32); // -3 (y): bstr(32)
        return new ByteArray(out.toByteArray());
    }

    /** Left-pad / strip a BigInteger's two's-complement bytes to exactly 32. */
    private static byte[] fixed32(byte[] raw) {
        byte[] out = new byte[32];
        if (raw.length == 32) {
            return raw;
        }
        if (raw.length == 33 && raw[0] == 0) { // leading sign byte
            System.arraycopy(raw, 1, out, 0, 32);
            return out;
        }
        System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
        return out;
    }

    private static byte[] sha256(byte[] in) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(in);
    }

    /** A credential repository holding exactly the one fixed test credential for {@code alice}. */
    private class FixedCredentialStore extends WebAuthnCredentialStore {
        @Override
        public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
            Set<PublicKeyCredentialDescriptor> out = new LinkedHashSet<>();
            if (USERNAME.equals(username)) {
                out.add(PublicKeyCredentialDescriptor.builder().id(credentialId).build());
            }
            return out;
        }

        @Override
        public Optional<ByteArray> getUserHandleForUsername(String username) {
            return USERNAME.equals(username) ? Optional.of(userHandle) : Optional.empty();
        }

        @Override
        public Optional<String> getUsernameForUserHandle(ByteArray handle) {
            return handle.equals(userHandle) ? Optional.of(USERNAME) : Optional.empty();
        }

        @Override
        public Optional<RegisteredCredential> lookup(ByteArray credId, ByteArray handle) {
            if (credentialId.equals(credId) && userHandle.equals(handle)) {
                return Optional.of(registered());
            }
            return Optional.empty();
        }

        @Override
        public Set<RegisteredCredential> lookupAll(ByteArray credId) {
            return credentialId.equals(credId) ? Collections.singleton(registered()) : Collections.emptySet();
        }

        private RegisteredCredential registered() {
            return RegisteredCredential.builder()
                    .credentialId(credentialId)
                    .userHandle(userHandle)
                    .publicKeyCose(coseKey)
                    .signatureCount(0L)
                    .build();
        }
    }
}
