// Point Jahia's mail delivery at the stack's Mailpit container so the email_code factor can
// actually deliver its one-time codes, and the reset-request flow can notify an admin.
//
// As of Jahia 8.2.4.0 this is an OSGi configuration (PID org.jahia.modules.mail) consumed by a
// separate mail-service module - NOT the old MailService.store(MailSettings) API. That API still
// compiles and still returns without throwing, but it persists nothing:
//
//   WARN [MailServiceImpl] - MailServiceImpl.store(MailSettings) is deprecated and no longer
//                            persists anything; configure mail via the OSGi
//                            org.jahia.modules.mail configuration instead.
//
// sendMessage() likewise returns "successfully" while delivering nothing, so a stale setup here
// fails completely silently: the spec just times out waiting for a mail nobody ever sent. That is
// exactly how this drifted unnoticed, so prefer failing loudly - the assertions at the end throw
// if the configuration did not take.
//
// The mail-service MODULE is installed by tests/assets/provisioning.yml at stack startup. This
// fixture only (re)applies the configuration, so a spec can guarantee it regardless of what an
// earlier spec left behind. Both are needed; the config alone does nothing without the module.
//
// BundleUtils, not getBundleContext().getServiceReference(): the console's framework context
// cannot see ConfigurationAdmin directly (returns null). Same pattern as setUpaEnabledFactors.
def ca = org.jahia.osgi.BundleUtils.getOsgiService("org.osgi.service.cm.ConfigurationAdmin", null)
def cfg = ca.getConfiguration("org.jahia.modules.mail", null)
def props = cfg.getProperties() ?: new Hashtable()

// SMTP_SERVER_URL is set in docker-compose.yml (smtp://smtp-server:1025); parse it rather than
// hardcoding, so this cannot drift from the compose config. Fall back to the compose default.
String smtpUrl = System.getenv("SMTP_SERVER_URL") ?: "smtp://smtp-server:1025"
def matcher = (smtpUrl =~ /^smtps?:\/\/([^:\/]+)(?::(\d+))?/)
String host = matcher ? matcher[0][1] : "smtp-server"
String port = (matcher && matcher[0][2]) ? matcher[0][2] : "1025"

props.put("disabled", "false")
props.put("smtp.host", host)
props.put("smtp.port", port)
// Mailpit accepts anonymous plaintext SMTP - no auth, no TLS.
props.put("smtp.auth", "false")
props.put("smtp.starttls", "false")
props.put("smtp.ssl", "false")
props.put("default.from", "noreply@smtp-server.localhost")
props.put("default.recipient", "admin@smtp-server.localhost")
cfg.update(props)

// Fail loudly rather than let a spec time out on a mail that was never going to be sent.
def applied = ca.getConfiguration("org.jahia.modules.mail", null).getProperties()
assert applied?.get("smtp.host") == host : "mail config did not apply (smtp.host)"
assert applied?.get("disabled") == "false" : "mail config did not apply (disabled)"
log.info("Mail configured for the test stack: host=" + host + " port=" + port)
return "mail configured: " + host + ":" + port
