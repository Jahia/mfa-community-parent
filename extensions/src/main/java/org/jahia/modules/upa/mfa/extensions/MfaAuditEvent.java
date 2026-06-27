package org.jahia.modules.upa.mfa.extensions;

/**
 * Immutable view of one MFA audit event, shared by every factor's audit log (TOTP, WebAuthn, ...).
 * <p>
 * Built through {@link Builder} rather than a 6-argument constructor (Sonar S107) - the project
 * targets Java 11, so a record is not available.
 */
public final class MfaAuditEvent {

    private final String eventType;
    private final String outcome;
    private final String userId;
    private final String siteKey;
    private final long timestamp;
    private final String detail;

    private MfaAuditEvent(Builder builder) {
        this.eventType = builder.eventType;
        this.outcome = builder.outcome;
        this.userId = builder.userId;
        this.siteKey = builder.siteKey;
        this.timestamp = builder.timestamp;
        this.detail = builder.detail;
    }

    public String getEventType() { return eventType; }
    public String getOutcome()   { return outcome; }
    public String getUserId()    { return userId; }
    public String getSiteKey()   { return siteKey; }
    public long getTimestamp()   { return timestamp; }
    public String getDetail()    { return detail; }

    public static Builder builder() {
        return new Builder();
    }

    /** Fluent builder for {@link MfaAuditEvent}. */
    public static final class Builder {
        private String eventType;
        private String outcome;
        private String userId;
        private String siteKey;
        private long timestamp;
        private String detail;

        private Builder() {
            // use MfaAuditEvent.builder()
        }

        public Builder eventType(String eventType) { this.eventType = eventType; return this; }
        public Builder outcome(String outcome)     { this.outcome = outcome; return this; }
        public Builder userId(String userId)       { this.userId = userId; return this; }
        public Builder siteKey(String siteKey)     { this.siteKey = siteKey; return this; }
        public Builder timestamp(long timestamp)   { this.timestamp = timestamp; return this; }
        public Builder detail(String detail)       { this.detail = detail; return this; }

        public MfaAuditEvent build() {
            return new MfaAuditEvent(this);
        }
    }
}
