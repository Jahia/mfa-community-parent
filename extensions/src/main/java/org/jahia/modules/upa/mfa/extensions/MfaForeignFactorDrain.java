package org.jahia.modules.upa.mfa.extensions;

import org.jahia.modules.upa.mfa.MfaFactorState;
import org.jahia.modules.upa.mfa.MfaService;
import org.jahia.modules.upa.mfa.MfaSession;
import org.jahia.services.content.decorator.JCRUserNode;
import org.jahia.services.security.AuthenticationOptions;
import org.jahia.services.security.AuthenticationService;
import org.jahia.services.security.InvalidSessionLoginException;
import org.jahia.services.usermanager.JahiaUserManagerService;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.login.AccountNotFoundException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.Serializable;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

/**
 * Completes the pick-one protocol for FOREIGN factors: factors listed in the global enforcement
 * policy whose provider ships outside this repository and therefore does not speak the
 * {@link SkippablePreparation} skip protocol. The canonical example is UPA's built-in
 * {@code email_code} provider, which always challenges — it never skips itself when a sibling
 * factor was already verified.
 *
 * <p>Why this is needed: UPA requires EVERY factor in {@code mfaEnabledFactors} to end up
 * verified before it authenticates the user ({@code MfaSessionContext.requiredFactors}). The
 * factors of this repository implement pick-one by skipping THEMSELVES (their {@code prepare}
 * returns a skipped preparation once another enforced factor is genuinely verified, and the
 * client drains the step). A foreign factor cannot do that, so once it is required it would
 * block the session forever for a user who chose to verify with TOTP or WebAuthn instead.</p>
 *
 * <p>Why not decorate or shadow the foreign provider: UPA's {@code FactorRegistry} keeps one
 * provider per factor type in a map with plain {@code put} overwrite semantics, and unbinding
 * the losing duplicate evicts the winner's entry ({@code remove(key, value)}). Registering a
 * second {@code email_code} provider would make the authentication path depend on bundle bind
 * order. Instead, this service wraps the verification call sites this repository owns — a
 * deterministic chokepoint.</p>
 *
 * <p>After a GENUINE verification of an enforced factor (a real challenge, not a drained skip),
 * every remaining enforced factor that has no {@link MfaSiteProvider} registered is marked
 * verified with a {@link ForeignDrainedPreparation} skip marker — so it can never satisfy
 * pick-one for anyone else — and, if that completes the session, the user is authenticated
 * exactly the way UPA's {@code MfaServiceImpl} does it after a normal verification.</p>
 *
 * <p>The reverse order needs no help here: when the user genuinely verifies the foreign factor
 * first (e.g. picks "Email code" in the chooser), the remaining native factors skip themselves
 * through their own pick-one rows and the session completes inside UPA.</p>
 */
@Component(service = MfaForeignFactorDrain.class, immediate = true)
public class MfaForeignFactorDrain {

    private static final Logger logger = LoggerFactory.getLogger(MfaForeignFactorDrain.class);

    private MfaService mfaService;
    private MfaGlobalPolicy globalPolicy;
    private AuthenticationService authenticationService;
    private JahiaUserManagerService userManagerService;
    private final List<MfaSiteProvider> siteProviders = new CopyOnWriteArrayList<>();

    @Reference
    public void setMfaService(MfaService mfaService) {
        this.mfaService = mfaService;
    }

    @Reference
    public void setGlobalPolicy(MfaGlobalPolicy globalPolicy) {
        this.globalPolicy = globalPolicy;
    }

    @Reference
    public void setAuthenticationService(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @Reference
    public void setUserManagerService(JahiaUserManagerService userManagerService) {
        this.userManagerService = userManagerService;
    }

    @Reference(service = MfaSiteProvider.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC)
    public void bindSiteProvider(MfaSiteProvider provider) {
        siteProviders.add(provider);
    }

    public void unbindSiteProvider(MfaSiteProvider provider) {
        siteProviders.remove(provider);
    }

    /**
     * Drop-in replacement for {@link MfaService#verifyFactor} to be used by the GraphQL verify
     * mutations of this repository's factors: verifies through the standard UPA chokepoint
     * (rate limiting, failure tracking, suspension all apply), then drains the foreign enforced
     * factors the genuine verification just satisfied.
     */
    public MfaSession verifyFactor(String factorType, Serializable verificationData,
                                   HttpServletRequest request, HttpServletResponse response) {
        MfaSession session = mfaService.verifyFactor(factorType, verificationData, request, response);
        drainForeignFactors(session, factorType, request, response);
        return session;
    }

    private void drainForeignFactors(MfaSession session, String verifiedFactor,
                                     HttpServletRequest request, HttpServletResponse response) {
        if (session == null || !session.isInitiated() || session.hasError()
                || !session.isFactorVerified(verifiedFactor)) {
            return;
        }
        // Only a GENUINE challenge satisfies pick-one. A factor whose own "verification" was a
        // drained skip must not release anything (circular-drain protection).
        if (SkippablePreparation.isSkipDrained(session, verifiedFactor)) {
            return;
        }
        // Pick-one only spans the enforced set: verifying an opt-in factor that is not part of
        // the policy never excuses an enforced one.
        if (!globalPolicy.isEnforced(verifiedFactor)) {
            return;
        }
        List<String> foreign = session.getRemainingFactors().stream()
                .filter(globalPolicy::isEnforced)
                .filter(this::isForeign)
                .collect(Collectors.toList());
        if (foreign.isEmpty()) {
            return;
        }
        String userId = session.getContext().getUserId();
        for (String factor : foreign) {
            MfaFactorState state = session.getOrCreateFactorState(factor);
            state.setPreparationResult(new ForeignDrainedPreparation());
            state.setPrepared(true);
            state.setVerified(true);
            logger.info("Drained foreign enforced factor {} for user {} (pick-one satisfied by {})",
                    factor, userId, verifiedFactor);
        }
        // UPA only authenticates inside its own verifyFactor, and the drain above happened after
        // that completion check ran — so when the drained factors were the last ones standing,
        // finish the session here the same way MfaServiceImpl.authenticateUser does.
        if (session.areAllRequiredFactorsCompleted()) {
            authenticate(session, request, response);
        }
    }

    /**
     * A factor is FOREIGN when its UPA provider cannot speak the skip protocol: either no
     * {@link MfaSiteProvider} is registered for it at all, or the registered one is a pure
     * adapter ({@link MfaSiteProvider#isForeignFactor()}) speaking about a provider implemented
     * elsewhere — like the email_code adapter of this very bundle. A native provider (totp,
     * webauthn) skips itself on the client walk-through and must be left alone.
     */
    private boolean isForeign(String factorType) {
        boolean represented = false;
        for (MfaSiteProvider provider : siteProviders) {
            if (factorType.equals(provider.getFactorType())) {
                if (provider.isForeignFactor()) {
                    return true;
                }
                represented = true;
            }
        }
        return !represented;
    }

    /**
     * Mirror of UPA's {@code MfaServiceImpl.authenticateUser}. Package-private so unit tests can
     * substitute a recorder — everything above it is plain session-state logic.
     */
    void authenticate(MfaSession session, HttpServletRequest request, HttpServletResponse response) {
        String userId = session.getContext().getUserId();
        JCRUserNode user = userManagerService.lookupUser(userId);
        if (user == null) {
            // The user verified a factor milliseconds ago; failing loudly beats leaving a
            // completed-but-unauthenticated session that bounces the client back to login.
            throw new IllegalStateException("MFA session user not found: " + userId);
        }
        AuthenticationOptions options = AuthenticationOptions.Builder.withDefaults()
                .shouldRememberMe(session.getContext().shouldRememberMe())
                .build();
        try {
            authenticationService.authenticate(user.getPath(), options, request, response);
        } catch (InvalidSessionLoginException e) {
            throw new IllegalStateException("Invalid session login", e);
        } catch (AccountNotFoundException e) {
            throw new IllegalStateException("Account not found", e);
        }
        logger.info("All MFA factors completed for user {} after foreign-factor drain, user authenticated", userId);
    }

    /**
     * The skip marker stored for a drained foreign factor. Implements
     * {@link SkippablePreparation} so the drained factor never satisfies the
     * "another enforced factor already verified" pick-one row of any sibling.
     */
    public static class ForeignDrainedPreparation implements Serializable, SkippablePreparation {
        private static final long serialVersionUID = 1L;

        @Override
        public boolean isSkipped() {
            return true;
        }
    }
}
