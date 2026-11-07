// Point Jahia's mail delivery at the stack's Mailpit container.
//
// Run by tests/assets/provisioning.yml (executeScript, file attached by ci.startup.sh).
//
// It configures BOTH mail paths, because the suite runs on both sides of a change:
//  - up to Jahia 8.2.3.x, mail is the core MailService, configured with
//    MailService.store(MailSettings). The mail-service module cannot even resolve there (it
//    needs a package that core only exports from 8.2.4.0).
//  - as of Jahia 8.2.4.0, mail is an OSGi configuration (PID org.jahia.modules.mail) consumed by
//    the separate mail-service module; store(MailSettings) still returns without throwing but
//    persists nothing (see provisioning.yml for the log evidence).
// Each half is harmless on the version that ignores it.
String smtpUrl = System.getenv("SMTP_SERVER_URL") ?: "smtp://smtp-server:1025"

def legacy = new org.jahia.services.mail.MailSettings()
legacy.setServiceActivated(true)
legacy.setUri(smtpUrl)
legacy.setFrom("noreply@smtp-server.localhost")
legacy.setTo("admin@smtp-server.localhost")
org.jahia.services.mail.MailService.getInstance().store(legacy)

def ca = org.jahia.osgi.BundleUtils.getOsgiService("org.osgi.service.cm.ConfigurationAdmin", null)
def cfg = ca.getConfiguration("org.jahia.modules.mail", null)
def props = cfg.getProperties() ?: new Hashtable()

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
