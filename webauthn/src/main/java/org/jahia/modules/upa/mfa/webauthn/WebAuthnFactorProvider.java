package org.jahia.modules.upa.mfa.webauthn;

import org.apache.commons.lang3.StringUtils;
import org.jahia.modules.upa.mfa.MfaException;
import org.jahia.modules.upa.mfa.MfaFactorProvider;
import org.jahia.modules.upa.mfa.PreparationContext;
import org.jahia.modules.upa.mfa.VerificationContext;
import org.jahia.services.usermanager.JahiaGroupManagerService;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.RepositoryException;
import java.io.IOException;
import java.io.Serializable;

/**
 * Phishing-resistant WebAuthn / FIDO2 second factor (W3C WebAuthn Level 2).
 * <p>
 * Authentication flow (mirrors {@code TotpFactorProvider} for the per-site enable/enforce/grace
 * policy, but the verification is an origin-bound assertion ceremony rather than a code):
 * <ul>
 *   <li>{@link #prepare} — when the site enables WebAuthn for an in-scope, registered user, start
 *       an assertion ({@code navigator.credentials.get}) with a fresh challenge and hand the
 *       options to the client; otherwise skip / enforce registration (with optional grace).</li>
 *   <li>{@link #verify} — validate the authenticator assertion (signature, origin/rpId binding,
 *       challenge match) and persist the new signature counter for clone detection.</li>
 * </ul>
 * Registration ({@code navigator.credentials.create}) is a self-service dashboard operation on
 * the GraphQL mutation, not part of this login provider.
 */
@Component(service = MfaFactorProvider.class, immediate = true)
public class WebAuthnFactorProvider implements MfaFactorProvider {

    private static final Logger logger = LoggerFactory.getLogger(WebAuthnFactorProvider.class);

    public static final String FACTOR_TYPE = "webauthn";

    public static final String ERROR_NOT_REGISTERED = "factor.webauthn.not_registered";
    public static final String ERROR_REGISTRATION_REQUIRED = "factor.webauthn.registration_required";
    public static final String ERROR_VERIFICATION_DATA_REQUIRED = "factor.webauthn.verification_data_required";
    public static final String ERROR_INTERNAL = "factor.webauthn.internal_error";

    private WebAuthnService webAuthnService;
    private WebAuthnCredentialStore credentialStore;
    private WebAuthnSiteSettingsStore siteSettingsStore;
    private WebAuthnAuditLog auditLog;
    private JahiaGroupManagerService groupManagerService;

    @Reference
    public void setWebAuthnService(WebAuthnService webAuthnService) { this.webAuthnService = webAuthnService; }

    @Reference
    public void setCredentialStore(WebAuthnCredentialStore credentialStore) { this.credentialStore = credentialStore; }

    @Reference
    public void setSiteSettingsStore(WebAuthnSiteSettingsStore siteSettingsStore) { this.siteSettingsStore = siteSettingsStore; }

    @Reference
    public void setAuditLog(WebAuthnAuditLog auditLog) { this.auditLog = auditLog; }

    @Reference
    public void setGroupManagerService(JahiaGroupManagerService groupManagerService) { this.groupManagerService = groupManagerService; }

    @Override
    public String getFactorType() {
        return FACTOR_TYPE;
    }

    @Override
    public Serializable prepare(PreparationContext preparationContext) throws MfaException {
        String userId = preparationContext.getSessionContext().getUserId();
        String siteKey = preparationContext.getSessionContext().getSiteKey();

        if (StringUtils.isNotBlank(siteKey)) {
            WebAuthnSiteSettingsStore.WebAuthnSiteSettings settings = loadSettings(siteKey);
            if (!settings.isEnabled()) {
                logger.debug("WebAuthn skipped for user {} (site '{}' disabled)", userId, siteKey);
                return new WebAuthnPreparationResult(true);
            }
            if (!isInScope(userId, settings.getEnabledGroups())) {
                logger.debug("WebAuthn skipped for user {} (not in any policy group on '{}')", userId, siteKey);
                return new WebAuthnPreparationResult(true);
            }
            if (!isRegistered(userId)) {
                return prepareUnregistered(userId, siteKey, settings);
            }
            return startAssertion(userId);
        }

        // No site context → require a registered user.
        if (!isRegistered(userId)) {
            throw new MfaException(ERROR_NOT_REGISTERED, "user", userId);
        }
        return startAssertion(userId);
    }

    private Serializable prepareUnregistered(String userId, String siteKey,
                                             WebAuthnSiteSettingsStore.WebAuthnSiteSettings settings)
            throws MfaException {
        if (!settings.isEnforced()) {
            return new WebAuthnPreparationResult(true);
        }
        long graceDays = settings.getGraceDays();
        if (graceDays <= 0) {
            auditLog.recordEvent("registrationRequired", "denied", userId, siteKey, "noGrace");
            throw new MfaException(ERROR_REGISTRATION_REQUIRED, "user", userId);
        }
        long now = System.currentTimeMillis();
        long graceStart;
        try {
            graceStart = credentialStore.getOrStartGraceMillis(userId, now);
        } catch (RepositoryException e) {
            logger.warn("Failed to read WebAuthn grace state for {}: {}", userId, e.getMessage());
            throw new MfaException(ERROR_INTERNAL);
        }
        long graceMillis = graceDays * 24L * 60L * 60L * 1000L;
        if ((now - graceStart) < graceMillis) {
            return new WebAuthnPreparationResult(true);
        }
        auditLog.recordEvent("registrationRequired", "denied", userId, siteKey, "graceExpired");
        throw new MfaException(ERROR_REGISTRATION_REQUIRED, "user", userId);
    }

    private Serializable startAssertion(String userId) throws MfaException {
        try {
            WebAuthnService.AssertionCeremony ceremony = webAuthnService.startAssertion(userId);
            return new WebAuthnPreparationResult(false, ceremony.getRequestJson(), ceremony.getClientOptionsJson());
        } catch (IOException e) {
            logger.warn("Failed to start WebAuthn assertion for {}: {}", userId, e.getMessage());
            throw new MfaException(ERROR_INTERNAL);
        }
    }

    @Override
    public boolean verify(VerificationContext verificationContext) throws MfaException {
        Serializable prep = verificationContext.getPreparationResult();
        if (prep instanceof WebAuthnPreparationResult && ((WebAuthnPreparationResult) prep).isSkipped()) {
            return true;
        }
        if (!(prep instanceof WebAuthnPreparationResult)) {
            throw new MfaException(ERROR_INTERNAL);
        }
        String requestJson = ((WebAuthnPreparationResult) prep).getRequestJson();

        String userId = verificationContext.getSessionContext().getUserId();
        Serializable raw = verificationContext.getVerificationData();
        if (!(raw instanceof String) || StringUtils.isBlank((String) raw)) {
            throw new MfaException(ERROR_VERIFICATION_DATA_REQUIRED);
        }
        String responseJson = (String) raw;
        String siteKey = verificationContext.getSessionContext().getSiteKey();

        boolean ok;
        try {
            WebAuthnService.AssertionOutcome outcome = webAuthnService.finishAssertion(requestJson, responseJson);
            ok = outcome.isSuccess();
            if (ok) {
                credentialStore.updateOnAssertion(userId, outcome.getCredentialIdB64(), outcome.getNewSignCount());
            }
        } catch (IOException e) {
            logger.warn("WebAuthn assertion verification error for {}: {}", userId, e.getMessage());
            ok = false;
        } catch (RepositoryException e) {
            logger.warn("Failed to persist WebAuthn sign counter for {}: {}", userId, e.getMessage());
            // Assertion was valid but the counter couldn't be recorded — refuse, to preserve
            // clone-detection integrity.
            ok = false;
        }
        auditLog.recordEvent("verify", ok ? "success" : "failure", userId, siteKey, null);
        return ok;
    }

    private WebAuthnSiteSettingsStore.WebAuthnSiteSettings loadSettings(String siteKey) throws MfaException {
        try {
            return siteSettingsStore.load(siteKey);
        } catch (RepositoryException e) {
            logger.warn("Failed to load WebAuthn site settings for {}: {}", siteKey, e.getMessage());
            throw new MfaException(ERROR_INTERNAL);
        }
    }

    private boolean isInScope(String userId, java.util.List<String> enabledGroups) throws MfaException {
        try {
            return credentialStore.isMemberOfAnyGroup(userId, enabledGroups, groupManagerService);
        } catch (RepositoryException e) {
            logger.warn("Failed to check group membership for {}: {}", userId, e.getMessage());
            throw new MfaException(ERROR_INTERNAL);
        }
    }

    private boolean isRegistered(String userId) throws MfaException {
        try {
            return credentialStore.hasCredentials(userId);
        } catch (RepositoryException e) {
            logger.warn("Failed to read WebAuthn credentials for {}: {}", userId, e.getMessage());
            throw new MfaException(ERROR_INTERNAL);
        }
    }
}
