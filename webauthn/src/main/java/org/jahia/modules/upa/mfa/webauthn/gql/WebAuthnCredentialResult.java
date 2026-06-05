package org.jahia.modules.upa.mfa.webauthn.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import org.jahia.modules.upa.mfa.webauthn.WebAuthnCredentialStore;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A registered WebAuthn credential as seen by the self-service dashboard (no key material).
 */
@GraphQLName("MfaWebauthnCredential")
@GraphQLDescription("A registered WebAuthn authenticator (passkey / security key).")
public class WebAuthnCredentialResult {

    private final String credentialId;
    private final String nickname;
    private final long signCount;
    private final long createdAt;
    private final long lastUsedAt;
    private final List<String> transports;
    private final String aaguid;

    public WebAuthnCredentialResult(WebAuthnCredentialStore.StoredCredential c) {
        this.credentialId = c.getCredentialId();
        this.nickname = c.getNickname();
        this.signCount = c.getSignCount();
        this.createdAt = c.getCreatedAt();
        this.lastUsedAt = c.getLastUsedAt();
        this.transports = c.getTransports() == null
                ? Collections.emptyList() : Collections.unmodifiableList(new ArrayList<>(c.getTransports()));
        this.aaguid = c.getAaguid();
    }

    @GraphQLField
    @GraphQLName("credentialId")
    @GraphQLDescription("Base64url credential id; the stable handle used to rename/delete it.")
    public String getCredentialId() { return credentialId; }

    @GraphQLField
    @GraphQLName("nickname")
    public String getNickname() { return nickname; }

    @GraphQLField
    @GraphQLName("signCount")
    @GraphQLDescription("Authenticator signature counter (clone-detection); 0 if the authenticator does not keep one.")
    public long getSignCount() { return signCount; }

    @GraphQLField
    @GraphQLName("createdAt")
    public long getCreatedAt() { return createdAt; }

    @GraphQLField
    @GraphQLName("lastUsedAt")
    @GraphQLDescription("Epoch-millis of the last successful assertion, or 0 if never used since registration.")
    public long getLastUsedAt() { return lastUsedAt; }

    @GraphQLField
    @GraphQLName("transports")
    @GraphQLDescription("Reported authenticator transports (usb, nfc, ble, internal, hybrid).")
    public List<String> getTransports() { return transports; }

    @GraphQLField
    @GraphQLName("aaguid")
    @GraphQLDescription("Base64url authenticator model identifier (AAGUID), if attested.")
    public String getAaguid() { return aaguid; }
}
