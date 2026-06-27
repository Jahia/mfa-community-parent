package org.jahia.modules.upa.mfa.totp;

import org.jahia.modules.upa.mfa.extensions.MfaManagementRateLimiterBase;
import org.jahia.services.usermanager.JahiaUserManagerService;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

/**
 * Per-user attempt counter that throttles TOTP code checks issued by the management GraphQL
 * mutations ({@code confirmEnroll}, {@code regenerateBackupCodes}, {@code disable}, and the
 * privileged {@code enroll(force=true)}).
 * <p>
 * The {@code verify} mutation is already protected by UPA's {@code MfaServiceImpl} lockout; the
 * management surface is protected here because it accepts a code without going through
 * {@code verifyFactor}. The window arithmetic and cluster-safe JCR persistence live in the shared
 * {@link MfaManagementRateLimiterBase}; this subclass supplies the distinct {@code upaTotp:}
 * namespace.
 */
@Component(service = TotpManagementRateLimiter.class, immediate = true)
public class TotpManagementRateLimiter extends MfaManagementRateLimiterBase {

    static final String MIXIN_LOCKOUT = "upaTotp:lockout";
    static final String PROP_FAILED_ATTEMPTS = "upaTotp:failedAttempts";
    static final String PROP_WINDOW_START = "upaTotp:windowStart";

    @Reference
    public void setUserManagerService(JahiaUserManagerService userManagerService) {
        setUserManagerServiceInternal(userManagerService);
    }

    @Override protected String mixinLockout()       { return MIXIN_LOCKOUT; }
    @Override protected String propFailedAttempts()  { return PROP_FAILED_ATTEMPTS; }
    @Override protected String propWindowStart()     { return PROP_WINDOW_START; }
    @Override protected String factorLabel()         { return "TOTP"; }
}
