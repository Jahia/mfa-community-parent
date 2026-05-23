package org.jahia.modules.upa.mfa.totp.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;

@GraphQLName("MfaTotpSiteSettingsResult")
@GraphQLDescription("Per-site TOTP settings: whether the factor is active and whether enrollment is enforced.")
public class TotpSiteSettingsResult {

    private final String siteKey;
    private final boolean enabled;
    private final boolean enforced;

    public TotpSiteSettingsResult(String siteKey, boolean enabled, boolean enforced) {
        this.siteKey = siteKey;
        this.enabled = enabled;
        this.enforced = enforced;
    }

    @GraphQLField
    @GraphQLName("siteKey")
    public String getSiteKey() {
        return siteKey;
    }

    @GraphQLField
    @GraphQLName("enabled")
    @GraphQLDescription("True if TOTP MFA is active on this site. False means the factor is skipped at login.")
    public boolean isEnabled() {
        return enabled;
    }

    @GraphQLField
    @GraphQLName("enforced")
    @GraphQLDescription("True if every user of the site must enrol; non-enrolled users will be redirected to the enrollment page at login.")
    public boolean isEnforced() {
        return enforced;
    }
}
