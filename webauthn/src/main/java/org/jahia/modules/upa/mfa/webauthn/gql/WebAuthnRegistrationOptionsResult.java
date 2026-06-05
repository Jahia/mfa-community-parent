package org.jahia.modules.upa.mfa.webauthn.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;

/**
 * Result of {@code startRegistration}: the {@code navigator.credentials.create()} options JSON
 * (the registration challenge) the browser passes to the authenticator to mint a new passkey.
 */
@GraphQLName("MfaWebauthnRegistrationOptionsResult")
@GraphQLDescription("WebAuthn registration options: PublicKeyCredentialCreationOptions for navigator.credentials.create().")
public class WebAuthnRegistrationOptionsResult {

    private final String creationOptionsJson;

    public WebAuthnRegistrationOptionsResult(String creationOptionsJson) {
        this.creationOptionsJson = creationOptionsJson;
    }

    @GraphQLField
    @GraphQLName("publicKeyCredentialCreationOptions")
    @GraphQLDescription("JSON for navigator.credentials.create().")
    public String getPublicKeyCredentialCreationOptions() {
        return creationOptionsJson;
    }
}
