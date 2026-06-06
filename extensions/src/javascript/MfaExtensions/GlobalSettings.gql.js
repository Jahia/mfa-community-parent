import gql from 'graphql-tag';

export const ConfigurationQuery = gql`
    query MfaExtensionsConfiguration {
        mfaExtensionsConfiguration {
            enforcedFactors
            graceDays
            loginGateEnabled
            loginGateIpWhitelist
            loginUrl
            logoutUrl
            registeredFactors
        }
    }
`;

export const SaveConfigurationMutation = gql`
    mutation MfaExtensionsSaveConfiguration(
        $enforcedFactors: [String]
        $graceDays: Int
        $loginGateEnabled: Boolean
        $loginGateIpWhitelist: String
        $loginUrl: String
        $logoutUrl: String
    ) {
        mfaExtensionsSaveConfiguration(
            enforcedFactors: $enforcedFactors
            graceDays: $graceDays
            loginGateEnabled: $loginGateEnabled
            loginGateIpWhitelist: $loginGateIpWhitelist
            loginUrl: $loginUrl
            logoutUrl: $logoutUrl
        ) {
            enforcedFactors
            graceDays
            loginGateEnabled
            loginGateIpWhitelist
            loginUrl
            logoutUrl
            registeredFactors
        }
    }
`;
