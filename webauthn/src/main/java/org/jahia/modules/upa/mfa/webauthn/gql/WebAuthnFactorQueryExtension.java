package org.jahia.modules.upa.mfa.webauthn.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import graphql.annotations.annotationTypes.GraphQLTypeExtension;
import org.jahia.modules.graphql.provider.dxm.DXGraphQLProvider;

/**
 * Adds a top-level {@code mfaWebauthn} field on the GraphQL {@code Query} so the UI can read the
 * current user's credentials and the per-site policy. Attached to {@code DXGraphQLProvider.Query}
 * (the UPA {@code impl.gql} package is not exported by the UPA API bundle).
 */
@GraphQLTypeExtension(DXGraphQLProvider.Query.class)
public class WebAuthnFactorQueryExtension {

    private WebAuthnFactorQueryExtension() {
        // not instantiated
    }

    @GraphQLField
    @GraphQLName("mfaWebauthn")
    @GraphQLDescription("Read-only WebAuthn / FIDO2 factor operations")
    public static WebAuthnFactorQuery mfaWebauthn() {
        return new WebAuthnFactorQuery();
    }
}
