import org.jahia.services.mail.MailSettings
import org.jahia.services.mail.MailService

// Activate Jahia's mail service against the stack's Mailpit SMTP container so the
// email_code factor can actually deliver its one-time codes. Run from the email spec's
// before() through cy.executeGroovy (provisioning executeScript) - the ci.startup.sh
// groovyConsole curl does not reliably execute, leaving mail inactive and sends failing.
MailSettings settings = new MailSettings()
settings.setServiceActivated(true)
settings.setUri("smtp://smtp-server:1025")
settings.setFrom("noreply@smtp-server.localhost")
settings.setTo("admin@smtp-server.localhost")
MailService.getInstance().store(settings)
