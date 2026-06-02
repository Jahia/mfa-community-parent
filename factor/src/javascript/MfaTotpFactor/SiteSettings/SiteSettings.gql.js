import gql from 'graphql-tag';

export const SiteSettingsQuery = gql`
    query MfaTotpSiteSettings($siteKey: String!) {
        mfaTotp {
            siteSettings(siteKey: $siteKey) {
                siteKey
                enabled
                enforced
            }
        }
    }
`;

export const SetSiteSettingsMutation = gql`
    mutation MfaTotpSetSiteSettings(
        $siteKey: String!
        $enabled: Boolean!
        $enforced: Boolean!
    ) {
        upa {
            mfaFactors {
                totp {
                    setSiteSettings(siteKey: $siteKey, enabled: $enabled, enforced: $enforced) {
                        siteKey
                        enabled
                        enforced
                    }
                }
            }
        }
    }
`;
