package org.jahia.modules.upa.mfa.extensions.internal;

import org.jahia.modules.upa.mfa.extensions.MfaSiteProvider;
import org.jahia.services.content.decorator.JCRUserNode;
import org.jahia.services.usermanager.JahiaUserManagerService;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

import javax.jcr.RepositoryException;

/**
 * {@link MfaSiteProvider} adapter speaking for UPA's BUILT-IN {@code email_code} factor.
 *
 * <p>UPA ships the email-code provider inside its api bundle (package
 * {@code org.jahia.modules.upa.mfa.emailcode}, deliberately NOT exported) and registers it only
 * against UPA's own {@code MfaFactorProvider} SPI — so none of the cross-factor infrastructure
 * of this bundle can see it: the chooser filter ({@code MfaFactorDirectory}), the
 * "sibling enforced factor configured" pick-one row of the native providers, the
 * {@code /cms/login} gate's activation check, and the enforcement options of the administration
 * UI. This adapter closes that gap without touching UPA:</p>
 *
 * <ul>
 *   <li><b>configured for user</b> == the profile carries a non-blank {@code j:email} — exactly
 *       the property UPA's provider sends the code to. There is no enrollment concept;</li>
 *   <li><b>per-site activation</b> does not exist for email: enabled everywhere;</li>
 *   <li><b>NOT inline-enrollable</b>: the sign-in flow cannot add an email address to a profile,
 *       so the inline-enrollment chooser must never offer it.</li>
 * </ul>
 *
 * <p>Side effect worth knowing: once {@code email_code} is enforced, a user owning a
 * {@code j:email} "owns an enforced factor", which closes pre-auth inline enrollment for them
 * (the anti-takeover barrier in the factor mutations) — correct, because they can complete
 * sign-in with the email challenge and enroll a stronger factor from their dashboard.</p>
 */
@Component(service = MfaSiteProvider.class, immediate = true)
public class EmailCodeFactorAdapter implements MfaSiteProvider {

    /** UPA's {@code EmailCodeFactorProvider.FACTOR_TYPE}; redefined because its package is unexported. */
    public static final String FACTOR_TYPE = "email_code";

    private JahiaUserManagerService userManagerService;

    @Reference
    public void setUserManagerService(JahiaUserManagerService userManagerService) {
        this.userManagerService = userManagerService;
    }

    @Override
    public String getFactorType() {
        return FACTOR_TYPE;
    }

    @Override
    public boolean isEnabledForSite(String siteKey) {
        return true;
    }

    @Override
    public boolean isAnySiteEnabled() {
        return true;
    }

    @Override
    public boolean isInlineEnrollable() {
        return false;
    }

    @Override
    public boolean isForeignFactor() {
        // This adapter only SPEAKS ABOUT the factor — UPA's provider, which it cannot touch,
        // never skips itself, so the foreign-factor drain must release it on pick-one.
        return true;
    }

    @Override
    public boolean isConfiguredForUser(String userId) {
        JCRUserNode user = userManagerService.lookupUser(userId);
        if (user == null) {
            return false;
        }
        try {
            String email = user.hasProperty("j:email") ? user.getProperty("j:email").getString() : null;
            return email != null && !email.trim().isEmpty();
        } catch (RepositoryException e) {
            // Fail CLOSED per the MfaSiteProvider error contract: access-control callers (the
            // login gate) must treat an unreadable backend as "cannot answer", not as "no".
            throw new IllegalStateException("Could not read j:email for user " + userId, e);
        }
    }
}
