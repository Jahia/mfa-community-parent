package org.jahia.modules.upa.mfa.webauthn.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import org.jahia.modules.upa.mfa.webauthn.WebAuthnCredentialStore;

import java.util.List;

@GraphQLName("MfaWebauthnEnrollmentReport")
@GraphQLDescription("Aggregate WebAuthn registration report across users.")
public class WebAuthnEnrollmentReportResult {

    private final WebAuthnCredentialStore.RegistrationReport report;

    public WebAuthnEnrollmentReportResult(WebAuthnCredentialStore.RegistrationReport report) {
        this.report = report;
    }

    @GraphQLField @GraphQLName("totalUsers")
    public long getTotalUsers() { return report.getTotalUsers(); }

    @GraphQLField @GraphQLName("registeredUsers")
    public long getRegisteredUsers() { return report.getRegisteredUsers(); }

    @GraphQLField @GraphQLName("notRegistered")
    @GraphQLDescription("Capped list of usernames with no registered authenticator.")
    public List<String> getNotRegistered() { return report.getNotRegistered(); }

    @GraphQLField @GraphQLName("truncated")
    @GraphQLDescription("True if the notRegistered list was capped.")
    public boolean isTruncated() { return report.isTruncated(); }
}
