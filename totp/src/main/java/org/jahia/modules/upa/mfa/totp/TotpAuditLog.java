package org.jahia.modules.upa.mfa.totp;

import org.jahia.modules.upa.mfa.extensions.MfaAuditLogBase;
import org.osgi.service.component.annotations.Component;

/**
 * Append-only audit trail for TOTP MFA events (enroll, confirm, verify, disable, regenerate,
 * admin reset, lockout). Events are stored as {@code upaTotp:auditEvent} nodes under
 * {@code /settings/mfaTotpAuditLog} via a system session, and queried back (newest first, scoped
 * by site) for the admin reporting UI.
 * <p>
 * The recording / querying / node-creation / 500-row cap live in the shared
 * {@link MfaAuditLogBase}; this subclass only supplies the distinct {@code upaTotp:} namespace.
 * Recording is best-effort: an audit failure is logged but never breaks the audited operation.
 * Codes/secrets are never written to the trail.
 */
@Component(service = TotpAuditLog.class, immediate = true)
public class TotpAuditLog extends MfaAuditLogBase {

    private static final String LOG_PATH = "/settings/mfaTotpAuditLog";
    private static final String LOG_NODE_NAME = "mfaTotpAuditLog";
    private static final String NT_LOG = "upaTotp:auditLog";
    private static final String NT_EVENT = "upaTotp:auditEvent";

    static final String PROP_EVENT_TYPE = "upaTotp:eventType";
    static final String PROP_OUTCOME = "upaTotp:outcome";
    static final String PROP_USER_ID = "upaTotp:userId";
    static final String PROP_SITE_KEY = "upaTotp:siteKey";
    static final String PROP_TIMESTAMP = "upaTotp:timestamp";
    static final String PROP_DETAIL = "upaTotp:detail";

    @Override protected String logPath()        { return LOG_PATH; }
    @Override protected String logNodeName()    { return LOG_NODE_NAME; }
    @Override protected String logNodeType()    { return NT_LOG; }
    @Override protected String eventNodeType()  { return NT_EVENT; }
    @Override protected String propEventType()  { return PROP_EVENT_TYPE; }
    @Override protected String propOutcome()    { return PROP_OUTCOME; }
    @Override protected String propUserId()     { return PROP_USER_ID; }
    @Override protected String propSiteKey()    { return PROP_SITE_KEY; }
    @Override protected String propTimestamp()  { return PROP_TIMESTAMP; }
    @Override protected String propDetail()     { return PROP_DETAIL; }
    @Override protected String factorLabel()    { return "TOTP"; }
}
