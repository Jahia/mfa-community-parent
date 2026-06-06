package org.jahia.modules.upa.mfa.extensions.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import graphql.annotations.annotationTypes.GraphQLTypeExtension;
import org.jahia.modules.graphql.provider.dxm.DXGraphQLProvider;
import org.jahia.modules.graphql.provider.dxm.DataFetchingException;
import org.jahia.modules.graphql.provider.dxm.security.GraphQLRequiresPermission;
import org.jahia.modules.upa.mfa.extensions.MfaFactorDirectory;
import org.jahia.osgi.BundleUtils;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

/**
 * Adds the top-level {@code mfaExtensionsConfiguration} query exposing the global MFA
 * configuration (PID {@code org.jahia.modules.mfa.extensions}) to the server administration UI.
 * Server-admin only.
 */
@GraphQLTypeExtension(DXGraphQLProvider.Query.class)
public class MfaExtensionsQueryExtension {

    private static final Logger logger = LoggerFactory.getLogger(MfaExtensionsQueryExtension.class);
    private static final String ERROR_INTERNAL = "mfaExtensions.internal_error";

    private MfaExtensionsQueryExtension() {
        // not instantiated
    }

    @GraphQLField
    @GraphQLName("mfaExtensionsConfiguration")
    @GraphQLDescription("The global MFA configuration (enforcement policy, /cms/login gate, login/logout routing). Server administrators only.")
    @GraphQLRequiresPermission("admin")
    public static MfaExtensionsConfiguration mfaExtensionsConfiguration() {
        try {
            ConfigurationAdmin configAdmin = BundleUtils.getOsgiService(ConfigurationAdmin.class, null);
            if (configAdmin == null) {
                throw new DataFetchingException(ERROR_INTERNAL);
            }
            Configuration config = configAdmin.getConfiguration(MfaExtensionsConfigSupport.PID, null);
            return MfaExtensionsConfigSupport.read(config.getProperties(), registeredFactors());
        } catch (IOException e) {
            logger.warn("Failed to read the MFA extensions configuration: {}", e.getMessage());
            throw new DataFetchingException(ERROR_INTERNAL);
        }
    }

    static List<String> registeredFactors() {
        MfaFactorDirectory directory = BundleUtils.getOsgiService(MfaFactorDirectory.class, null);
        return directory == null ? Collections.emptyList() : directory.getRegisteredFactorTypes();
    }
}
