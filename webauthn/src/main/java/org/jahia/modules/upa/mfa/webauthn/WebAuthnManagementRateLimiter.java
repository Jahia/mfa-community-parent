package org.jahia.modules.upa.mfa.webauthn;

import org.jahia.modules.upa.mfa.extensions.MfaManagementRateLimiterBase;
import org.jahia.services.usermanager.JahiaUserManagerService;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

/**
 * Per-user attempt counter that throttles the WebAuthn registration management surface
 * ({@code startRegistration} / {@code finishRegistration} on the pre-authentication inline
 * enrollment path, where the caller has only proved the password).
 * <p>
 * The {@code verify} mutation is already protected by UPA's {@code MfaServiceImpl} lockout. The
 * window arithmetic and cluster-safe JCR persistence live in the shared
 * {@link MfaManagementRateLimiterBase}; this subclass supplies the distinct {@code upaWebauthn:}
 * namespace.
 */
@Component(service = WebAuthnManagementRateLimiter.class, immediate = true)
public class WebAuthnManagementRateLimiter extends MfaManagementRateLimiterBase {

    static final String MIXIN_LOCKOUT = "upaWebauthn:lockout";
    static final String PROP_FAILED_ATTEMPTS = "upaWebauthn:failedAttempts";
    static final String PROP_WINDOW_START = "upaWebauthn:windowStart";

    @Reference
    public void setUserManagerService(JahiaUserManagerService userManagerService) {
        setUserManagerServiceInternal(userManagerService);
    }

    @Override protected String mixinLockout()       { return MIXIN_LOCKOUT; }
    @Override protected String propFailedAttempts()  { return PROP_FAILED_ATTEMPTS; }
    @Override protected String propWindowStart()     { return PROP_WINDOW_START; }
    @Override protected String factorLabel()         { return "WebAuthn"; }
}
