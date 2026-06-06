package org.jahia.modules.upa.mfa.webauthn.gql;

import com.yubico.webauthn.data.ByteArray;
import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import graphql.annotations.annotationTypes.GraphQLNonNull;
import graphql.schema.DataFetchingEnvironment;
import org.apache.commons.lang3.StringUtils;
import org.jahia.modules.graphql.provider.dxm.DataFetchingException;
import org.jahia.modules.graphql.provider.dxm.osgi.annotations.GraphQLOsgiService;
import org.jahia.modules.graphql.provider.dxm.util.ContextUtil;
import org.jahia.modules.upa.mfa.MfaService;
import org.jahia.modules.upa.mfa.MfaSession;
import org.jahia.modules.upa.mfa.extensions.MfaFactorDirectory;
import org.jahia.modules.upa.mfa.extensions.MfaGlobalPolicy;
import org.jahia.modules.upa.mfa.gql.Result;
import org.jahia.modules.upa.mfa.webauthn.WebAuthnAuditLog;
import org.jahia.modules.upa.mfa.webauthn.WebAuthnCredentialStore;
import org.jahia.modules.upa.mfa.webauthn.WebAuthnManagementRateLimiter;
import org.jahia.modules.upa.mfa.webauthn.WebAuthnService;
import org.jahia.modules.upa.mfa.webauthn.WebAuthnSiteSettingsStore;
import org.jahia.services.content.JCRSessionFactory;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.usermanager.JahiaUser;
import org.jahia.services.usermanager.JahiaUserManagerService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.jcr.RepositoryException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.jahia.modules.upa.mfa.webauthn.WebAuthnFactorProvider.FACTOR_TYPE;

/**
 * GraphQL mutation surface for the WebAuthn factor:
 * login ceremony ({@code prepare} / {@code verify}), self-service registration management
 * ({@code startRegistration} / {@code finishRegistration} / {@code renameCredential} /
 * {@code deleteCredential}), and site administration ({@code setSiteSettings} /
 * {@code resetUserWebauthn}).
 * <p>
 * {@code prepare} / {@code verify} go through {@link MfaService} so UPA's lockout applies. The
 * self-service registration ceremony stores its transient challenge on the HTTP session between
 * the two calls (the user is already authenticated). Admin operations are gated by
 * {@link WebAuthnAdminAccess}.
 */
@GraphQLName("MfaWebauthnFactorMutation")
@GraphQLDescription("Mutations for the WebAuthn MFA factor")
public class WebAuthnFactorMutation {

    private static final Logger logger = LoggerFactory.getLogger(WebAuthnFactorMutation.class);

    private static final String ERROR_NOT_AUTHENTICATED = "factor.webauthn.not_authenticated";
    private static final String ERROR_INTERNAL = "factor.webauthn.internal_error";
    private static final String ERROR_NO_REGISTRATION_STATE = "factor.webauthn.no_registration_state";
    private static final String ERROR_REGISTRATION_FAILED = "factor.webauthn.registration_failed";
    private static final String ERROR_LOCKED_OUT = "factor.webauthn.locked_out";
    private static final String OUTCOME_SUCCESS = "success";

    /** HTTP session attribute holding the transient registration challenge (creation options JSON). */
    private static final String REGISTRATION_STATE_ATTR = "upa.mfa.webauthn.registrationState";

    private MfaService mfaService;
    private WebAuthnService webAuthnService;
    private WebAuthnCredentialStore credentialStore;
    private WebAuthnSiteSettingsStore siteSettingsStore;
    private WebAuthnAuditLog auditLog;
    private MfaGlobalPolicy globalPolicy;
    private MfaFactorDirectory factorDirectory;
    private WebAuthnManagementRateLimiter rateLimiter;

    @Inject @GraphQLOsgiService
    public void setMfaService(MfaService mfaService) { this.mfaService = mfaService; }

    @Inject @GraphQLOsgiService
    public void setGlobalPolicy(MfaGlobalPolicy globalPolicy) { this.globalPolicy = globalPolicy; }

    @Inject @GraphQLOsgiService
    public void setFactorDirectory(MfaFactorDirectory factorDirectory) { this.factorDirectory = factorDirectory; }

    @Inject @GraphQLOsgiService
    public void setRateLimiter(WebAuthnManagementRateLimiter rateLimiter) { this.rateLimiter = rateLimiter; }

    @Inject @GraphQLOsgiService
    public void setWebAuthnService(WebAuthnService webAuthnService) { this.webAuthnService = webAuthnService; }

    @Inject @GraphQLOsgiService
    public void setCredentialStore(WebAuthnCredentialStore credentialStore) { this.credentialStore = credentialStore; }

    @Inject @GraphQLOsgiService
    public void setSiteSettingsStore(WebAuthnSiteSettingsStore siteSettingsStore) { this.siteSettingsStore = siteSettingsStore; }

    @Inject @GraphQLOsgiService
    public void setAuditLog(WebAuthnAuditLog auditLog) { this.auditLog = auditLog; }

    // --- Login ceremony ------------------------------------------------------------------

    @GraphQLField
    @GraphQLName("prepare")
    @GraphQLDescription("Start a WebAuthn assertion; returns the navigator.credentials.get() options.")
    public WebAuthnPreparation prepare(DataFetchingEnvironment environment) {
        HttpServletRequest request = ContextUtil.getHttpServletRequest(environment.getGraphQlContext());
        HttpServletResponse response = ContextUtil.getHttpServletResponse(environment.getGraphQlContext());
        MfaSession session = mfaService.prepareFactor(FACTOR_TYPE, request, response);
        Object prep = session.getOrCreateFactorState(FACTOR_TYPE).getPreparationResult();
        String optionsJson = null;
        boolean skipped = false;
        if (prep instanceof org.jahia.modules.upa.mfa.webauthn.WebAuthnPreparationResult) {
            org.jahia.modules.upa.mfa.webauthn.WebAuthnPreparationResult result =
                    (org.jahia.modules.upa.mfa.webauthn.WebAuthnPreparationResult) prep;
            optionsJson = result.getClientOptionsJson();
            skipped = result.isSkipped();
        }
        return new WebAuthnPreparation(session, optionsJson, skipped);
    }

    @GraphQLField
    @GraphQLName("verify")
    @GraphQLDescription("Finish a WebAuthn assertion with the navigator.credentials.get() response JSON.")
    public Result verify(
            @GraphQLName("assertion") @GraphQLNonNull String assertion,
            DataFetchingEnvironment environment) {
        HttpServletRequest request = ContextUtil.getHttpServletRequest(environment.getGraphQlContext());
        HttpServletResponse response = ContextUtil.getHttpServletResponse(environment.getGraphQlContext());
        MfaSession session = mfaService.verifyFactor(FACTOR_TYPE, assertion, request, response);
        return new Result(session);
    }

    // --- Self-service registration -------------------------------------------------------

    @GraphQLField
    @GraphQLName("startRegistration")
    @GraphQLDescription("Begin registering a new authenticator; returns navigator.credentials.create() options.")
    public WebAuthnRegistrationOptionsResult startRegistration(DataFetchingEnvironment environment) {
        HttpServletRequest request = ContextUtil.getHttpServletRequest(environment.getGraphQlContext());
        JahiaUser user = currentNonGuestUser();
        boolean preAuth = (user == null);
        String userId = preAuth ? requirePreAuthRegistrationSubject(request) : user.getName();
        if (preAuth && rateLimiter.isLockedOut(userId)) {
            throw new DataFetchingException(ERROR_LOCKED_OUT);
        }
        try {
            ByteArray userHandle = credentialStore.userHandleFor(userId)
                    .orElseThrow(() -> new DataFetchingException(ERROR_INTERNAL));
            WebAuthnService.RegistrationCeremony ceremony =
                    webAuthnService.startRegistration(userId, userId, userHandle);
            request.getSession(true).setAttribute(REGISTRATION_STATE_ATTR, ceremony.getRequestJson());
            return new WebAuthnRegistrationOptionsResult(ceremony.getClientOptionsJson());
        } catch (IOException | RepositoryException e) {
            logger.warn("Failed to start WebAuthn registration for {}: {}", userId, e.getMessage());
            throw new DataFetchingException(ERROR_INTERNAL);
        }
    }

    @GraphQLField
    @GraphQLName("finishRegistration")
    @GraphQLDescription("Finish registering an authenticator with the navigator.credentials.create() response JSON.")
    public WebAuthnStatusResult finishRegistration(
            @GraphQLName("response") @GraphQLNonNull String response,
            @GraphQLName("nickname") String nickname,
            DataFetchingEnvironment environment) {
        HttpServletRequest request = ContextUtil.getHttpServletRequest(environment.getGraphQlContext());
        JahiaUser user = currentNonGuestUser();
        boolean preAuth = (user == null);
        String userId = preAuth ? requirePreAuthRegistrationSubject(request) : user.getName();
        if (preAuth && rateLimiter.isLockedOut(userId)) {
            throw new DataFetchingException(ERROR_LOCKED_OUT);
        }
        HttpSession http = request.getSession(false);
        String requestJson = http == null ? null : (String) http.getAttribute(REGISTRATION_STATE_ATTR);
        if (StringUtils.isBlank(requestJson)) {
            throw new DataFetchingException(ERROR_NO_REGISTRATION_STATE);
        }
        try {
            WebAuthnService.RegistrationOutcome outcome = webAuthnService.finishRegistration(requestJson, response);
            String handle = credentialStore.userHandleFor(userId).map(ByteArray::getBase64Url).orElse(null);
            credentialStore.addCredential(userId, new WebAuthnCredentialStore.NewCredential(
                    outcome.getCredentialIdB64(), outcome.getPublicKeyCoseB64(), outcome.getSignCount(),
                    handle, outcome.getTransports(), outcome.getAaguidB64(), nickname));
            credentialStore.clearGrace(userId);
            http.removeAttribute(REGISTRATION_STATE_ATTR);
            if (preAuth) {
                rateLimiter.recordSuccess(userId);
            }
            auditLog.recordEvent("register", OUTCOME_SUCCESS, userId, null, preAuth ? "inlineLogin" : null);
            // On the pre-auth path the session is NOT completed here: registration produces an
            // attestation, while login needs an assertion — the client immediately runs the
            // standard prepare → navigator.credentials.get() → verify ceremony to finish signing in.
            return new WebAuthnStatusResult(loadCredentialResults(userId));
        } catch (com.yubico.webauthn.exception.RegistrationFailedException e) {
            if (preAuth) {
                rateLimiter.recordFailure(userId);
            }
            logger.warn("WebAuthn registration rejected for {}: {}", userId, e.getMessage());
            throw new DataFetchingException(ERROR_REGISTRATION_FAILED);
        } catch (IOException | RepositoryException e) {
            logger.warn("Failed to finish WebAuthn registration for {}: {}", userId, e.getMessage());
            throw new DataFetchingException(ERROR_INTERNAL);
        }
    }

    @GraphQLField
    @GraphQLName("renameCredential")
    @GraphQLDescription("Rename one of the current user's registered authenticators.")
    public boolean renameCredential(
            @GraphQLName("credentialId") @GraphQLNonNull String credentialId,
            @GraphQLName("nickname") @GraphQLNonNull String nickname,
            DataFetchingEnvironment environment) {
        String userId = requireUser().getName();
        try {
            return credentialStore.renameCredential(userId, credentialId, nickname);
        } catch (RepositoryException e) {
            throw new DataFetchingException(ERROR_INTERNAL);
        }
    }

    @GraphQLField
    @GraphQLName("deleteCredential")
    @GraphQLDescription("Remove one of the current user's registered authenticators.")
    public boolean deleteCredential(
            @GraphQLName("credentialId") @GraphQLNonNull String credentialId,
            DataFetchingEnvironment environment) {
        String userId = requireUser().getName();
        try {
            boolean removed = credentialStore.deleteCredential(userId, credentialId);
            if (removed) {
                auditLog.recordEvent("deregister", OUTCOME_SUCCESS, userId, null, null);
            }
            return removed;
        } catch (RepositoryException e) {
            throw new DataFetchingException(ERROR_INTERNAL);
        }
    }

    // --- Site administration -------------------------------------------------------------

    @GraphQLField
    @GraphQLName("setSiteSettings")
    @GraphQLDescription("Set the per-site WebAuthn policy (enabled / enabledGroups). Enforcement is global "
            + "(org.jahia.modules.mfa.extensions). Caller must be a site admin.")
    public WebAuthnSiteSettingsResult setSiteSettings(
            @GraphQLName("siteKey") @GraphQLNonNull String siteKey,
            @GraphQLName("enabled") @GraphQLNonNull Boolean enabled,
            @GraphQLName("enabledGroups") List<String> enabledGroups) {
        if (StringUtils.isBlank(siteKey)) {
            throw new DataFetchingException("siteKey must not be blank");
        }
        JCRSessionWrapper session = WebAuthnAdminAccess.requireSiteAdmin(siteKey);
        try {
            siteSettingsStore.save(session, siteKey, new WebAuthnSiteSettingsStore.WebAuthnSiteSettings(
                    enabled, enabledGroups));
            auditLog.recordEvent("setSiteSettings", OUTCOME_SUCCESS, currentUserName(), siteKey,
                    "enabled=" + enabled);
            return new WebAuthnSiteSettingsResult(siteKey, enabled, enabledGroups);
        } catch (RepositoryException e) {
            logger.warn("Failed to save WebAuthn site settings for {}: {}", siteKey, e.getMessage());
            throw new DataFetchingException(ERROR_INTERNAL);
        }
    }

    @GraphQLField
    @GraphQLName("resetUserWebauthn")
    @GraphQLDescription("Admin recovery: clear ALL of a user's WebAuthn credentials. Caller must be a site admin.")
    public boolean resetUserWebauthn(
            @GraphQLName("userId") @GraphQLNonNull String userId,
            @GraphQLName("siteKey") @GraphQLNonNull String siteKey) {
        if (StringUtils.isBlank(userId)) {
            throw new DataFetchingException("userId must not be blank");
        }
        WebAuthnAdminAccess.requireSiteAdmin(siteKey);
        String admin = currentUserName();
        try {
            credentialStore.deleteAll(userId);
            credentialStore.clearGrace(userId);
            auditLog.recordEvent("reset", OUTCOME_SUCCESS, userId, siteKey, "by=" + admin);
            return true;
        } catch (RepositoryException e) {
            logger.warn("Failed to reset WebAuthn for {}: {}", userId, e.getMessage());
            throw new DataFetchingException(ERROR_INTERNAL);
        }
    }

    // --- helpers -------------------------------------------------------------------------

    private List<WebAuthnCredentialResult> loadCredentialResults(String userId) throws RepositoryException {
        List<WebAuthnCredentialResult> out = new ArrayList<>();
        credentialStore.listCredentials(userId).forEach(c -> out.add(new WebAuthnCredentialResult(c)));
        return out;
    }

    private static JahiaUser requireUser() {
        JahiaUser user = currentNonGuestUser();
        if (user == null) {
            throw new DataFetchingException(ERROR_NOT_AUTHENTICATED);
        }
        return user;
    }

    /**
     * The authenticated (non-guest) caller, or {@code null}. CRITICAL: Jahia resolves
     * unauthenticated GraphQL requests to the GUEST user, not to {@code null} — treating guest
     * as authenticated would silently run self-service operations against the literal
     * {@code guest} account (and bypass the pre-auth registration guard).
     */
    private static JahiaUser currentNonGuestUser() {
        JahiaUser user = JCRSessionFactory.getInstance().getCurrentUser();
        return (user == null || JahiaUserManagerService.isGuest(user)) ? null : user;
    }

    /**
     * The pre-authentication inline-registration guard. Registering an authenticator without an
     * authenticated user is allowed ONLY when ALL of the following hold (fails CLOSED on doubt):
     * <ol>
     *   <li>an initiated, error-free MFA session exists (the password was already validated);</li>
     *   <li>this factor is part of the global enforcement policy;</li>
     *   <li>the session user owns NO globally enforced factor — the anti-takeover barrier: a
     *       caller who only proved the password must never add an authenticator to an account
     *       that already has a second factor.</li>
     * </ol>
     *
     * @return the MFA-session user id (the registration subject)
     */
    private String requirePreAuthRegistrationSubject(HttpServletRequest request) {
        MfaSession session = mfaService.getMfaSession(request);
        if (session == null || !session.isInitiated() || session.hasError()) {
            throw new DataFetchingException(ERROR_NOT_AUTHENTICATED);
        }
        if (!globalPolicy.isEnforced(FACTOR_TYPE)) {
            throw new DataFetchingException(ERROR_NOT_AUTHENTICATED);
        }
        String userId = session.getContext().getUserId();
        boolean ownsEnforcedFactor;
        try {
            ownsEnforcedFactor = factorDirectory.hasAnyEnforcedFactorConfigured(userId);
        } catch (RuntimeException e) {
            logger.error("Could not evaluate factor ownership for user {} (refusing pre-auth registration): {}",
                    userId, e.getMessage());
            throw new DataFetchingException(ERROR_INTERNAL);
        }
        if (ownsEnforcedFactor) {
            logger.warn("Refused pre-auth WebAuthn registration for user {}: an enforced factor is already "
                    + "configured", userId);
            throw new DataFetchingException(ERROR_NOT_AUTHENTICATED);
        }
        return userId;
    }

    private static String currentUserName() {
        JahiaUser u = JCRSessionFactory.getInstance().getCurrentUser();
        return u == null ? "<anonymous>" : u.getName();
    }
}
