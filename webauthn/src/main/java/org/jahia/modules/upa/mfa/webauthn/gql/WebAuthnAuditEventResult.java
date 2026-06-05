package org.jahia.modules.upa.mfa.webauthn.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import org.jahia.modules.upa.mfa.webauthn.WebAuthnAuditLog;

@GraphQLName("MfaWebauthnAuditEvent")
@GraphQLDescription("A single WebAuthn audit event.")
public class WebAuthnAuditEventResult {

    private final WebAuthnAuditLog.AuditEvent event;

    public WebAuthnAuditEventResult(WebAuthnAuditLog.AuditEvent event) {
        this.event = event;
    }

    @GraphQLField @GraphQLName("eventType")
    public String getEventType() { return event.getEventType(); }

    @GraphQLField @GraphQLName("outcome")
    public String getOutcome() { return event.getOutcome(); }

    @GraphQLField @GraphQLName("userId")
    public String getUserId() { return event.getUserId(); }

    @GraphQLField @GraphQLName("timestamp")
    public long getTimestamp() { return event.getTimestamp(); }

    @GraphQLField @GraphQLName("detail")
    public String getDetail() { return event.getDetail(); }
}
