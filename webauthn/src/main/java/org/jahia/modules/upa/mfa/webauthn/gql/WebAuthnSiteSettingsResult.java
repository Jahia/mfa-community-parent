package org.jahia.modules.upa.mfa.webauthn.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@GraphQLName("MfaWebauthnSiteSettingsResult")
@GraphQLDescription("Per-site WebAuthn policy: active flag, enforcement, grace period and group scoping.")
public class WebAuthnSiteSettingsResult {

    private final String siteKey;
    private final boolean enabled;
    private final boolean enforced;
    private final long graceDays;
    private final List<String> enabledGroups;

    public WebAuthnSiteSettingsResult(String siteKey, boolean enabled, boolean enforced,
                                      long graceDays, List<String> enabledGroups) {
        this.siteKey = siteKey;
        this.enabled = enabled;
        this.enforced = enforced;
        this.graceDays = graceDays;
        this.enabledGroups = enabledGroups == null
                ? Collections.emptyList() : Collections.unmodifiableList(new ArrayList<>(enabledGroups));
    }

    @GraphQLField @GraphQLName("siteKey")
    public String getSiteKey() { return siteKey; }

    @GraphQLField @GraphQLName("enabled")
    @GraphQLDescription("True if WebAuthn MFA is active on this site.")
    public boolean isEnabled() { return enabled; }

    @GraphQLField @GraphQLName("enforced")
    @GraphQLDescription("True if registration is mandatory (subject to the grace period).")
    public boolean isEnforced() { return enforced; }

    @GraphQLField @GraphQLName("graceDays")
    @GraphQLDescription("When enforcing, days a newly-prompted, not-yet-registered user may still sign in (0 = immediate).")
    public long getGraceDays() { return graceDays; }

    @GraphQLField @GraphQLName("enabledGroups")
    @GraphQLDescription("If non-empty, the policy applies ONLY to members of these groups; empty = all users.")
    public List<String> getEnabledGroups() { return enabledGroups; }
}
