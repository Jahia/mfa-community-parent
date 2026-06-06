package org.jahia.modules.upa.mfa.totp.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@GraphQLName("MfaTotpSiteSettingsResult")
@GraphQLDescription("Per-site TOTP policy: active flag, group scoping and login/logout routing. "
        + "Enforcement is global — see the org.jahia.modules.mfa.extensions configuration.")
public class TotpSiteSettingsResult {

    private final String siteKey;
    private final boolean enabled;
    private final List<String> enabledGroups;
    private final String loginUrl;
    private final String logoutUrl;

    public TotpSiteSettingsResult(String siteKey, boolean enabled, List<String> enabledGroups,
                                  String loginUrl, String logoutUrl) {
        this.siteKey = siteKey;
        this.enabled = enabled;
        this.enabledGroups = enabledGroups == null
                ? Collections.emptyList() : Collections.unmodifiableList(new ArrayList<>(enabledGroups));
        this.loginUrl = loginUrl;
        this.logoutUrl = logoutUrl;
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
    @GraphQLName("enabledGroups")
    @GraphQLDescription("If non-empty, the policy applies ONLY to members of these groups; empty = all users of the site.")
    public List<String> getEnabledGroups() {
        return enabledGroups;
    }

    @GraphQLField
    @GraphQLName("loginUrl")
    @GraphQLDescription("Per-site custom login page URL used by the shared MfaLoginLogoutProvider; null = fall back to global config.")
    public String getLoginUrl() {
        return loginUrl;
    }

    @GraphQLField
    @GraphQLName("logoutUrl")
    @GraphQLDescription("Per-site custom logout page URL used by the shared MfaLoginLogoutProvider; null = fall back to global config.")
    public String getLogoutUrl() {
        return logoutUrl;
    }
}
