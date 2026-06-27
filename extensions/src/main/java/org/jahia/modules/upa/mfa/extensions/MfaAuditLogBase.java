package org.jahia.modules.upa.mfa.extensions;

import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.content.JCRTemplate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.Node;
import javax.jcr.NodeIterator;
import javax.jcr.RepositoryException;
import javax.jcr.query.Query;
import javax.jcr.query.QueryResult;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Append-only audit-trail base shared by every MFA factor's audit log. Events are stored as
 * factor-specific {@code auditEvent} nodes under a factor-specific log path via a system session,
 * and queried back (newest first, scoped by site) for the admin reporting UI.
 * <p>
 * Subclasses supply only the factor's JCR namespace prefix, node-types and log path (TOTP keeps
 * its distinct {@code upaTotp:} prefix, WebAuthn {@code upaWebauthn:}); the recording, querying,
 * node-creation and 500-row cap are implemented once here.
 * <p>
 * Recording is best-effort: an audit failure is logged but never breaks the operation being
 * audited. Codes/secrets are never written to the trail.
 */
public abstract class MfaAuditLogBase {

    private static final Logger logger = LoggerFactory.getLogger(MfaAuditLogBase.class);

    /** Hard upper bound on rows returned by {@link #recentEvents}. */
    private static final int MAX_EVENTS = 500;

    /** The JCR path of the per-factor audit-log node (e.g. {@code /settings/mfaTotpAuditLog}). */
    protected abstract String logPath();

    /** The node name (relative to {@code /settings}) of the audit-log node (e.g. {@code mfaTotpAuditLog}). */
    protected abstract String logNodeName();

    /** The audit-log node type (e.g. {@code upaTotp:auditLog}). */
    protected abstract String logNodeType();

    /** The audit-event node type (e.g. {@code upaTotp:auditEvent}). */
    protected abstract String eventNodeType();

    /** Property name for the event type (e.g. {@code upaTotp:eventType}). */
    protected abstract String propEventType();

    /** Property name for the outcome (e.g. {@code upaTotp:outcome}). */
    protected abstract String propOutcome();

    /** Property name for the user id (e.g. {@code upaTotp:userId}). */
    protected abstract String propUserId();

    /** Property name for the site key (e.g. {@code upaTotp:siteKey}). */
    protected abstract String propSiteKey();

    /** Property name for the timestamp (e.g. {@code upaTotp:timestamp}). */
    protected abstract String propTimestamp();

    /** Property name for the detail (e.g. {@code upaTotp:detail}). */
    protected abstract String propDetail();

    /** Human-readable factor name for log messages (e.g. {@code "TOTP"}). */
    protected abstract String factorLabel();

    /** Record an event. Best-effort: never throws into the caller's flow. */
    public void recordEvent(String eventType, String outcome, String userId, String siteKey, String detail) {
        try {
            JCRTemplate.getInstance().doExecuteWithSystemSession(session -> {
                JCRNodeWrapper log = ensureLogNode(session);
                JCRNodeWrapper event = log.addNode("e-" + UUID.randomUUID(), eventNodeType());
                event.setProperty(propEventType(), safe(eventType));
                event.setProperty(propOutcome(), safe(outcome));
                event.setProperty(propUserId(), safe(userId));
                event.setProperty(propSiteKey(), safe(siteKey));
                event.setProperty(propTimestamp(), System.currentTimeMillis());
                if (detail != null) {
                    event.setProperty(propDetail(), detail);
                }
                session.save();
                return null;
            });
        } catch (RepositoryException e) {
            logger.warn("Failed to record {} audit event {}/{} for user {}: {}",
                    factorLabel(), eventType, outcome, userId, e.getMessage());
        }
    }

    /** Return the most recent events for a site, newest first, capped at {@code limit} (max 500). */
    public List<MfaAuditEvent> recentEvents(String siteKey, int limit) throws RepositoryException {
        int cap = Math.max(1, Math.min(limit, MAX_EVENTS));
        return JCRTemplate.getInstance().doExecuteWithSystemSession(session -> {
            List<MfaAuditEvent> out = new ArrayList<>();
            String sql = "SELECT * FROM [" + eventNodeType() + "] WHERE [" + propSiteKey() + "] = $site"
                    + " ORDER BY [" + propTimestamp() + "] DESC";
            Query q = session.getWorkspace().getQueryManager().createQuery(sql, Query.JCR_SQL2);
            q.bindValue("site", session.getValueFactory().createValue(siteKey == null ? "" : siteKey));
            q.setLimit(cap);
            QueryResult result = q.execute();
            NodeIterator it = result.getNodes();
            while (it.hasNext()) {
                Node n = it.nextNode();
                out.add(MfaAuditEvent.builder()
                        .eventType(strProp(n, propEventType()))
                        .outcome(strProp(n, propOutcome()))
                        .userId(strProp(n, propUserId()))
                        .siteKey(strProp(n, propSiteKey()))
                        .timestamp(n.hasProperty(propTimestamp()) ? n.getProperty(propTimestamp()).getLong() : 0L)
                        .detail(strProp(n, propDetail()))
                        .build());
            }
            return out;
        });
    }

    private JCRNodeWrapper ensureLogNode(JCRSessionWrapper session) throws RepositoryException {
        if (session.nodeExists(logPath())) {
            return session.getNode(logPath());
        }
        JCRNodeWrapper settings = session.getNode("/settings");
        JCRNodeWrapper log = settings.addNode(logNodeName(), logNodeType());
        session.save();
        return log;
    }

    private static String safe(String s) {
        return s == null ? "" : s;
    }

    private static String strProp(Node n, String name) throws RepositoryException {
        return n.hasProperty(name) ? n.getProperty(name).getString() : null;
    }
}
