package org.jahia.modules.upa.mfa.extensions;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Immutable snapshot of the per-site MFA configuration for a single site: the factor-agnostic
 * login/logout URLs plus, per factor type, whether the factor is enabled and the (optional) group
 * restriction. This replaces the per-factor JCR {@code *:siteSettings} mixins — the data now lives
 * in a single file-backed OSGi factory configuration per site (see {@link MfaSiteConfigService}).
 * <p>
 * The {@code with*} methods return copies, so a factor can update only its own slice without
 * clobbering another factor's keys in the shared per-site file.
 */
public final class MfaSiteConfig {

    /**
     * The shared, immutable singleton snapshot returned for any site that has no {@code .cfg}
     * file (and as the read-modify-write base in {@link MfaSiteConfigService#save}). It carries no
     * login/logout URL (both {@code null} = fall back to the global config) and no factor slices,
     * so every {@link #isEnabled} call resolves to {@code false} and {@link #isAllDefault} is
     * {@code true}. Being immutable, it can be safely shared across all sites and threads.
     */
    public static final MfaSiteConfig EMPTY = new MfaSiteConfig(null, null, Collections.emptyMap());

    private final String loginUrl;
    private final String logoutUrl;
    private final Map<String, FactorSiteState> factors;

    public MfaSiteConfig(String loginUrl, String logoutUrl, Map<String, FactorSiteState> factors) {
        this.loginUrl = trimToNull(loginUrl);
        this.logoutUrl = trimToNull(logoutUrl);
        Map<String, FactorSiteState> copy = new HashMap<>();
        if (factors != null) {
            factors.forEach((type, state) -> {
                if (type != null && state != null) {
                    copy.put(type.toLowerCase(Locale.ROOT), state);
                }
            });
        }
        this.factors = Collections.unmodifiableMap(copy);
    }

    /** Per-site custom login page URL, or {@code null} (falls back to the global config). */
    public String getLoginUrl() {
        return loginUrl;
    }

    /** Per-site custom logout page URL, or {@code null} (falls back to the global config). */
    public String getLogoutUrl() {
        return logoutUrl;
    }

    /** The state of one factor on this site; {@link FactorSiteState#DISABLED} when absent. */
    public FactorSiteState factor(String factorType) {
        if (factorType == null) {
            return FactorSiteState.DISABLED;
        }
        return factors.getOrDefault(factorType.toLowerCase(Locale.ROOT), FactorSiteState.DISABLED);
    }

    public boolean isEnabled(String factorType) {
        return factor(factorType).isEnabled();
    }

    public List<String> enabledGroups(String factorType) {
        return factor(factorType).getGroups();
    }

    /** The per-factor states, keyed by lowercased factor type (unmodifiable). */
    public Map<String, FactorSiteState> factors() {
        return factors;
    }

    /** {@code true} when nothing is configured (no URLs, every factor disabled with no groups). */
    public boolean isAllDefault() {
        if (loginUrl != null || logoutUrl != null) {
            return false;
        }
        for (FactorSiteState state : factors.values()) {
            if (!state.isDefault()) {
                return false;
            }
        }
        return true;
    }

    /** Copy of this config with the URLs replaced (factor slices untouched). */
    public MfaSiteConfig withUrls(String newLoginUrl, String newLogoutUrl) {
        return new MfaSiteConfig(newLoginUrl, newLogoutUrl, factors);
    }

    /** Copy of this config with one factor's slice replaced (other factors untouched). */
    public MfaSiteConfig withFactor(String factorType, boolean enabled, List<String> groups) {
        Map<String, FactorSiteState> merged = new HashMap<>(factors);
        merged.put(factorType.toLowerCase(Locale.ROOT), new FactorSiteState(enabled, groups));
        return new MfaSiteConfig(loginUrl, logoutUrl, merged);
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    /** One factor's per-site state: enabled flag + the (cleaned) group restriction. */
    public static final class FactorSiteState {

        public static final FactorSiteState DISABLED = new FactorSiteState(false, Collections.emptyList());

        /**
         * A group name is serialized verbatim into the shared {@code .cfg} as
         * {@code <factor>.enabledGroups=<join(",")>}. A name carrying CR, LF, {@code ','},
         * {@code '='} or {@code '#'} could inject arbitrary config lines (e.g. forge a
         * {@code loginUrl=} or flip another factor), so we restrict names to a safe alphabet at
         * this single chokepoint. See {@link #clean(List)}.
         */
        private static final Pattern SAFE_GROUP_NAME = Pattern.compile("[A-Za-z0-9_-]+");

        private final boolean enabled;
        private final List<String> groups;

        public FactorSiteState(boolean enabled, List<String> groups) {
            this.enabled = enabled;
            this.groups = clean(groups);
        }

        public boolean isEnabled() {
            return enabled;
        }

        /** Non-blank, trimmed group names; empty = applies to all users of the site. */
        public List<String> getGroups() {
            return groups;
        }

        /** {@code true} when this factor contributes nothing (disabled, no groups). */
        public boolean isDefault() {
            return !enabled && groups.isEmpty();
        }

        /**
         * Trim, drop blanks, and reject any group name not matching {@link #SAFE_GROUP_NAME} —
         * the single chokepoint that prevents config injection through the shared {@code .cfg}.
         *
         * @throws IllegalArgumentException when a name contains an unsafe character (CR, LF,
         *         {@code ','}, {@code '='}, {@code '#'}, whitespace, ...); the GraphQL layer maps
         *         this to a field error
         */
        private static List<String> clean(List<String> input) {
            if (input == null) {
                return Collections.emptyList();
            }
            List<String> cleaned = new ArrayList<>();
            for (String group : input) {
                String trimmed = group == null ? "" : group.trim();
                if (trimmed.isEmpty()) {
                    continue;
                }
                if (!SAFE_GROUP_NAME.matcher(trimmed).matches()) {
                    throw new IllegalArgumentException("Invalid group name '" + trimmed
                            + "': only letters, digits, '_' and '-' are allowed (no commas, '=', '#', "
                            + "or line breaks, which would corrupt the per-site configuration file)");
                }
                cleaned.add(trimmed);
            }
            return Collections.unmodifiableList(cleaned);
        }
    }
}
