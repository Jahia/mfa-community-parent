package org.jahia.modules.upa.mfa.webauthn.gql;

import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import graphql.annotations.annotationTypes.GraphQLTypeExtension;
import org.jahia.modules.upa.mfa.gql.FactorsMutation;

/**
 * Adds the {@code webauthn} field on the UPA {@code FactorsMutation} GraphQL type.
 */
@GraphQLTypeExtension(FactorsMutation.class)
public class WebAuthnFactorMutationExtension {

    private WebAuthnFactorMutationExtension() {
        // not instantiated
    }

    @GraphQLField
    @GraphQLName("webauthn")
    public static WebAuthnFactorMutation webauthn() {
        return new WebAuthnFactorMutation();
    }
}
