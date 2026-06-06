package org.jahia.modules.upa.mfa.extensions;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Aggregated view over every registered {@link MfaSiteProvider}, combined with the
 * {@link MfaGlobalPolicy}. Used by security-sensitive callers (the pre-authentication inline
 * enrollment mutations) that need ONE answer across all factors.
 */
@Component(service = MfaFactorDirectory.class, immediate = true)
public class MfaFactorDirectory {

    private MfaGlobalPolicy globalPolicy;
    private final List<MfaSiteProvider> siteProviders = new CopyOnWriteArrayList<>();

    @Reference
    public void setGlobalPolicy(MfaGlobalPolicy globalPolicy) {
        this.globalPolicy = globalPolicy;
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
     * The factor types currently registered through the {@link MfaSiteProvider} SPI (distinct,
     * registration order). Used by the administration UI to offer one enforcement checkbox per
     * installed factor, and by the configuration mutation to refuse unknown factor names (a typo
     * in {@code enforcedFactors} would create an unsatisfiable policy).
     */
    public List<String> getRegisteredFactorTypes() {
        List<String> types = new ArrayList<>();
        for (MfaSiteProvider provider : siteProviders) {
            String type = provider.getFactorType();
            if (type != null && !types.contains(type)) {
                types.add(type);
            }
        }
        return Collections.unmodifiableList(types);
    }

    /**
     * Whether the user has at least one globally enforced factor configured.
     * <p>
     * <b>Error contract:</b> a provider that cannot answer (unhealthy repository) propagates its
     * unchecked exception — callers that guard pre-authentication enrollment MUST fail closed
     * (refuse the enrollment) rather than assume "not configured", because this check is the
     * anti-takeover barrier: an account that already owns a factor must never accept a new one
     * from a caller who only proved the password.
     */
    public boolean hasAnyEnforcedFactorConfigured(String userId) {
        for (MfaSiteProvider provider : siteProviders) {
            if (globalPolicy.isEnforced(provider.getFactorType()) && provider.isConfiguredForUser(userId)) {
                return true;
            }
        }
        return false;
    }
}
