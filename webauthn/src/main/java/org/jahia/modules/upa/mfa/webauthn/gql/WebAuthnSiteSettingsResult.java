package org.jahia.modules.upa.mfa.webauthn.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@GraphQLName("MfaWebauthnSiteSettingsResult")
@GraphQLDescription("Per-site WebAuthn policy: active flag and group scoping. "
        + "Enforcement is global — see the org.jahia.modules.mfa.extensions configuration.")
public class WebAuthnSiteSettingsResult {

    private final String siteKey;
    private final boolean enabled;
    private final List<String> enabledGroups;

    public WebAuthnSiteSettingsResult(String siteKey, boolean enabled, List<String> enabledGroups) {
        this.siteKey = siteKey;
        this.enabled = enabled;
        this.enabledGroups = enabledGroups == null
                ? Collections.emptyList() : Collections.unmodifiableList(new ArrayList<>(enabledGroups));
    }

    @GraphQLField @GraphQLName("siteKey")
    public String getSiteKey() { return siteKey; }

    @GraphQLField @GraphQLName("enabled")
    @GraphQLDescription("True if WebAuthn MFA is active on this site.")
    public boolean isEnabled() { return enabled; }

    @GraphQLField @GraphQLName("enabledGroups")
    @GraphQLDescription("If non-empty, the policy applies ONLY to members of these groups; empty = all users.")
    public List<String> getEnabledGroups() { return enabledGroups; }
}
