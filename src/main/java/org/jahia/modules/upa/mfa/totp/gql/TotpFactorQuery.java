package org.jahia.modules.upa.mfa.totp.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import org.jahia.modules.graphql.provider.dxm.DataFetchingException;
import org.jahia.modules.graphql.provider.dxm.osgi.annotations.GraphQLOsgiService;
import org.jahia.modules.upa.mfa.totp.TotpUserStore;
import org.jahia.services.content.JCRSessionFactory;
import org.jahia.services.usermanager.JahiaUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.jcr.RepositoryException;

/**
 * GraphQL read-only operations for the TOTP factor.
 */
@GraphQLName("MfaTotpFactorQuery")
@GraphQLDescription("Read-only operations for the TOTP MFA factor")
public class TotpFactorQuery {

    private static final Logger logger = LoggerFactory.getLogger(TotpFactorQuery.class);
    private static final String ERROR_NOT_AUTHENTICATED = "factor.totp.not_authenticated";
    private static final String ERROR_INTERNAL = "factor.totp.internal_error";

    private TotpUserStore userStore;

    @Inject
    @GraphQLOsgiService
    public void setUserStore(TotpUserStore userStore) {
        this.userStore = userStore;
    }

    @GraphQLField
    @GraphQLName("status")
    @GraphQLDescription("TOTP enrollment status for the currently authenticated user")
    public TotpStatusResult status() {
        JahiaUser user = JCRSessionFactory.getInstance().getCurrentUser();
        if (user == null) {
            throw new DataFetchingException(ERROR_NOT_AUTHENTICATED);
        }
        try {
            TotpUserStore.TotpUserSettings settings = userStore.load(user.getName());
            int remaining = settings.getBackupCodeHashes() == null ? 0 : settings.getBackupCodeHashes().size();
            return new TotpStatusResult(settings.isEnrolled(), remaining);
        } catch (RepositoryException e) {
            logger.warn("Failed to load TOTP settings for user {}: {}", user.getName(), e.getMessage());
            throw new DataFetchingException(ERROR_INTERNAL);
        }
    }
}
