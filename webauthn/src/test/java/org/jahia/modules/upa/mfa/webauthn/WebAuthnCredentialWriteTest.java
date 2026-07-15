package org.jahia.modules.upa.mfa.webauthn;

import org.jahia.services.content.JCRCallback;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.content.JCRTemplate;
import org.jahia.services.content.decorator.JCRUserNode;
import org.jahia.services.usermanager.JahiaUserManagerService;
import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.invocation.Invocation;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.mockingDetails;
import static org.mockito.Mockito.when;

/**
 * D6 (no-private-material sub-gap): a WebAuthn private key never leaves the authenticator, so
 * {@link WebAuthnCredentialStore#addCredential} must persist ONLY public material — credential id,
 * COSE <b>public</b> key, sign count, user handle, transports, aaguid, nickname, last-used. This
 * test captures every property written to the credential node and asserts the set is confined to
 * those public properties (in particular the public key IS stored and no private/secret property
 * ever is).
 */
public class WebAuthnCredentialWriteTest {

    /** The only properties the store is allowed to write on a credential node — all public. */
    private static final Set<String> ALLOWED_PROPS = new HashSet<>(Arrays.asList(
            WebAuthnCredentialStore.PROP_CREDENTIAL_ID,
            WebAuthnCredentialStore.PROP_PUBLIC_KEY_COSE,
            WebAuthnCredentialStore.PROP_SIGN_COUNT,
            WebAuthnCredentialStore.PROP_USER_HANDLE,
            WebAuthnCredentialStore.PROP_TRANSPORTS,
            WebAuthnCredentialStore.PROP_AAGUID,
            WebAuthnCredentialStore.PROP_NICKNAME,
            WebAuthnCredentialStore.PROP_LAST_USED_AT));

    @Test
    public void addCredential_writesOnlyPublicProperties_neverPrivateKeyMaterial() throws Exception {
        WebAuthnCredentialStore store = new WebAuthnCredentialStore();

        JCRNodeWrapper credentialNode = mock(JCRNodeWrapper.class);
        JCRUserNode user = mock(JCRUserNode.class);
        when(user.isNodeType(WebAuthnCredentialStore.MIXIN_USER_SETTINGS)).thenReturn(false);
        when(user.addNode(anyString(), eq(WebAuthnCredentialStore.NT_CREDENTIAL))).thenReturn(credentialNode);

        JahiaUserManagerService userManager = mock(JahiaUserManagerService.class);
        when(userManager.lookupUser(eq("alice"), any(JCRSessionWrapper.class))).thenReturn(user);
        store.setUserManagerService(userManager);

        JCRSessionWrapper session = mock(JCRSessionWrapper.class);
        JCRTemplate template = mock(JCRTemplate.class);
        when(template.doExecuteWithSystemSession(any())).thenAnswer(inv ->
                inv.getArgument(0, JCRCallback.class).doInJCR(session));

        WebAuthnCredentialStore.NewCredential newCredential = WebAuthnCredentialStore.NewCredential.builder()
                .credentialIdB64("Y3JlZA")
                .publicKeyCoseB64("cHVibGljS2V5Q29zZQ")
                .signCount(1L)
                .userHandleB64("dXNlckhhbmRsZQ")
                .transports(Arrays.asList("usb", "nfc"))
                .aaguid("YWFndWlk")
                .nickname("My key")
                .build();

        try (MockedStatic<JCRTemplate> statics = mockStatic(JCRTemplate.class)) {
            statics.when(JCRTemplate::getInstance).thenReturn(template);
            store.addCredential("alice", newCredential);
        }

        // Collect the NAME (first arg) of every setProperty(...) invocation on the credential node.
        List<String> writtenProps = mockingDetails(credentialNode).getInvocations().stream()
                .filter(i -> "setProperty".equals(i.getMethod().getName()))
                .map(WebAuthnCredentialWriteTest::firstStringArg)
                .collect(Collectors.toList());

        assertFalse("the store must write at least the public credential fields", writtenProps.isEmpty());
        assertTrue("the COSE PUBLIC key must be persisted",
                writtenProps.contains(WebAuthnCredentialStore.PROP_PUBLIC_KEY_COSE));
        for (String prop : writtenProps) {
            assertTrue("only public credential properties may be written, found: " + prop,
                    ALLOWED_PROPS.contains(prop));
            String lower = prop.toLowerCase();
            assertFalse("no private/secret property may be written: " + prop,
                    lower.contains("private") || lower.contains("secret") || lower.contains("privatekey"));
        }
    }

    private static String firstStringArg(Invocation invocation) {
        Object[] args = invocation.getArguments();
        return args.length > 0 && args[0] instanceof String ? (String) args[0] : String.valueOf(args.length > 0 ? args[0] : null);
    }
}
