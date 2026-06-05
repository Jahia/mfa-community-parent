package org.jahia.modules.upa.mfa.webauthn;

import java.io.Serializable;

/**
 * Preparation result for the WebAuthn login ceremony, stored in the {@code MfaFactorState}
 * between the {@code prepare} and {@code verify} GraphQL calls (it lives in the HTTP session).
 * <p>
 * Unlike TOTP, WebAuthn must hand the browser a fresh challenge: {@code clientOptionsJson} is the
 * {@code navigator.credentials.get()} input surfaced to the client, while {@code requestJson} is
 * the full serialized {@code AssertionRequest} kept server-side for {@code finishAssertion}.
 * When {@code skipped} is true (site disabled, user out of scope, or unenforced + unregistered),
 * {@link WebAuthnFactorProvider#verify} accepts any submission as a defensive backstop.
 */
public class WebAuthnPreparationResult implements Serializable {
    private static final long serialVersionUID = 1L;

    private final boolean skipped;
    private final String requestJson;
    private final String clientOptionsJson;

    public WebAuthnPreparationResult(boolean skipped) {
        this(skipped, null, null);
    }

    public WebAuthnPreparationResult(boolean skipped, String requestJson, String clientOptionsJson) {
        this.skipped = skipped;
        this.requestJson = requestJson;
        this.clientOptionsJson = clientOptionsJson;
    }

    public boolean isSkipped() {
        return skipped;
    }

    public String getRequestJson() {
        return requestJson;
    }

    public String getClientOptionsJson() {
        return clientOptionsJson;
    }
}
