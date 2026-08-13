// Point Jahia's mail delivery at the stack's Mailpit container.
//
// Kept for parity with the sibling Jahia test harnesses, which invoke this from ci.startup.sh.
// The authoritative setup for THIS harness is tests/assets/provisioning.yml (module install +
// PID configuration through the provisioning API), because the groovyConsole.jsp curl in
// ci.startup.sh does not reliably execute the script it uploads.
//
// As of Jahia 8.2.4.0 mail is an OSGi configuration (PID org.jahia.modules.mail) consumed by a
// separate mail-service module. The old MailService.store(MailSettings) API this file used to
// call still compiles and returns without throwing, but persists nothing and sends nothing -
// silently. See provisioning.yml for the log evidence.
def ca = org.jahia.osgi.BundleUtils.getOsgiService("org.osgi.service.cm.ConfigurationAdmin", null)
def cfg = ca.getConfiguration("org.jahia.modules.mail", null)
def props = cfg.getProperties() ?: new Hashtable()

String smtpUrl = System.getenv("SMTP_SERVER_URL") ?: "smtp://smtp-server:1025"
def matcher = (smtpUrl =~ /^smtps?:\/\/([^:\/]+)(?::(\d+))?/)
String host = matcher ? matcher[0][1] : "smtp-server"
String port = (matcher && matcher[0][2]) ? matcher[0][2] : "1025"

props.put("disabled", "false")
props.put("smtp.host", host)
props.put("smtp.port", port)
props.put("smtp.auth", "false")
props.put("smtp.starttls", "false")
props.put("smtp.ssl", "false")
props.put("default.from", "noreply@smtp-server.localhost")
props.put("default.recipient", "admin@smtp-server.localhost")
cfg.update(props)

log.info("Mail configured for the test stack: host=" + host + " port=" + port)
