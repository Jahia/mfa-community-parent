package org.jahia.modules.upa.mfa.extensions;

import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRTemplate;

import javax.jcr.RepositoryException;
import javax.jcr.Value;
import javax.jcr.query.Query;
import java.util.ArrayList;
import java.util.List;

/**
 * Shared per-site settings store base for the MFA factors. Centralizes the read of the
 * {@code enabledGroups} multi-valued property, the {@code isAnySiteEnabled} JCR_SQL2 query, and
 * the enabled+groups write loop. Subclasses keep their own snapshot value type and any extra
 * columns (TOTP adds {@code loginUrl}/{@code logoutUrl}), supplying the factor's mixin/property
 * names through the abstract accessors so the distinct {@code upaTotp:} / {@code upaWebauthn:}
 * prefixes are preserved.
 * <p>
 * Reads go through a system session. Writes go through the caller-provided (admin) session,
 * gated by a {@code siteAdmin} permission check in the GraphQL layer.
 */
public abstract class MfaSiteSettingsStoreBase {

    /** The site-settings mixin node type for this factor (e.g. {@code upaTotp:siteSettings}). */
    protected abstract String mixinSiteSettings();

    /** The {@code enabled} boolean property name (e.g. {@code upaTotp:enabled}). */
    protected abstract String propEnabled();

    /** The {@code enabledGroups} multi-valued property name (e.g. {@code upaTotp:enabledGroups}). */
    protected abstract String propEnabledGroups();

    /**
     * Whether at least one site currently has this factor {@code enabled}. Used by the shared
     * {@code /cms/login} gate on its no-resolvable-site code path: while the global policy
     * enforces this factor, any site with it enabled makes the legacy login endpoint a
     * second-factor bypass vector. (Enforcement itself is global - see {@link MfaGlobalPolicy}.)
     */
    public boolean isAnySiteEnabled() throws RepositoryException {
        return Boolean.TRUE.equals(JCRTemplate.getInstance().doExecuteWithSystemSession(session -> {
            Query query = session.getWorkspace().getQueryManager().createQuery(
                    "SELECT * FROM [" + mixinSiteSettings() + "] WHERE [" + propEnabled() + "] = true",
                    Query.JCR_SQL2);
            query.setLimit(1);
            return query.execute().getNodes().hasNext();
        }));
    }

    /** Read the {@code enabled} flag from a site node carrying the mixin. */
    protected boolean readEnabled(JCRNodeWrapper siteNode) throws RepositoryException {
        return siteNode.hasProperty(propEnabled()) && siteNode.getProperty(propEnabled()).getBoolean();
    }

    /** Read the non-blank, trimmed group names from the multi-valued enabledGroups property. */
    protected List<String> readGroups(JCRNodeWrapper siteNode) throws RepositoryException {
        List<String> groups = new ArrayList<>();
        if (!siteNode.hasProperty(propEnabledGroups())) {
            return groups;
        }
        for (Value v : siteNode.getProperty(propEnabledGroups()).getValues()) {
            String g = v.getString();
            if (g != null && !g.trim().isEmpty()) {
                groups.add(g.trim());
            }
        }
        return groups;
    }

    /** Apply the mixin if missing, then write the {@code enabled} flag and cleaned group list. */
    protected List<String> writeEnabledAndGroups(JCRNodeWrapper siteNode, boolean enabled,
                                                  List<String> enabledGroups) throws RepositoryException {
        if (!siteNode.isNodeType(mixinSiteSettings())) {
            siteNode.addMixin(mixinSiteSettings());
        }
        siteNode.setProperty(propEnabled(), enabled);
        List<String> cleaned = new ArrayList<>();
        if (enabledGroups != null) {
            for (String g : enabledGroups) {
                if (g != null && !g.trim().isEmpty()) {
                    cleaned.add(g.trim());
                }
            }
        }
        siteNode.setProperty(propEnabledGroups(), cleaned.toArray(new String[0]));
        return cleaned;
    }
}
