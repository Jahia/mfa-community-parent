package org.jahia.modules.upa.mfa.webauthn;

import org.jahia.modules.upa.mfa.extensions.MfaAuditLogBase;
import org.osgi.service.component.annotations.Component;

/**
 * Append-only audit trail for WebAuthn events (register, deregister, verify, admin reset).
 * Mirrors {@code TotpAuditLog}: {@code upaWebauthn:auditEvent} nodes under
 * {@code /settings/mfaWebauthnAuditLog}, written via a system session, queried newest-first per
 * site. The shared logic lives in {@link MfaAuditLogBase}; this subclass supplies the distinct
 * {@code upaWebauthn:} namespace. Best-effort — an audit failure never breaks the audited operation.
 */
@Component(service = WebAuthnAuditLog.class, immediate = true)
public class WebAuthnAuditLog extends MfaAuditLogBase {

    private static final String LOG_PATH = "/settings/mfaWebauthnAuditLog";
    private static final String LOG_NODE_NAME = "mfaWebauthnAuditLog";
    private static final String NT_LOG = "upaWebauthn:auditLog";
    private static final String NT_EVENT = "upaWebauthn:auditEvent";

    static final String PROP_EVENT_TYPE = "upaWebauthn:eventType";
    static final String PROP_OUTCOME = "upaWebauthn:outcome";
    static final String PROP_USER_ID = "upaWebauthn:userId";
    static final String PROP_SITE_KEY = "upaWebauthn:siteKey";
    static final String PROP_TIMESTAMP = "upaWebauthn:timestamp";
    static final String PROP_DETAIL = "upaWebauthn:detail";

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
    @Override protected String factorLabel()    { return "WebAuthn"; }
}
