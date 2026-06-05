package org.jahia.modules.upa.mfa.webauthn.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@GraphQLName("MfaWebauthnStatusResult")
@GraphQLDescription("The current user's WebAuthn registration status and registered credentials.")
public class WebAuthnStatusResult {

    private final boolean registered;
    private final List<WebAuthnCredentialResult> credentials;

    public WebAuthnStatusResult(List<WebAuthnCredentialResult> credentials) {
        this.credentials = credentials == null
                ? Collections.emptyList() : Collections.unmodifiableList(new ArrayList<>(credentials));
        this.registered = !this.credentials.isEmpty();
    }

    @GraphQLField @GraphQLName("registered")
    @GraphQLDescription("True if the user has at least one registered authenticator.")
    public boolean isRegistered() { return registered; }

    @GraphQLField @GraphQLName("credentials")
    public List<WebAuthnCredentialResult> getCredentials() { return credentials; }
}
