import React, {useEffect, useState} from 'react';
import {useTranslation} from 'react-i18next';
import {useQuery, useMutation} from '@apollo/client';
import {Button, Header, Typography, Loader} from '@jahia/moonstone';
import {ContentLayout} from '@jahia/moonstone-alpha';
import {SiteSettingsQuery, SetSiteSettingsMutation} from './SiteSettings.gql';

/**
 * Resolve the current site key. Jahia's admin shell exposes it on
 * window.contextJsParameters; we fall back to the URL path
 * /jahia/administration/sites/<siteKey>/...  for robustness.
 */
function resolveSiteKey() {
    const fromCtx = window.contextJsParameters && window.contextJsParameters.siteKey;
    if (fromCtx) {
        return fromCtx;
    }
    const match = /\/sites\/([^/]+)/.exec(window.location.pathname || '');
    return match ? match[1] : null;
}

const SiteSettings = () => {
    const {t} = useTranslation('mfa-totp-factor');
    const siteKey = resolveSiteKey();

    const [enabled, setEnabled] = useState(false);
    const [enforced, setEnforced] = useState(false);
    const [savedAt, setSavedAt] = useState(null);
    const [errorKey, setErrorKey] = useState(null);

    const {data, loading} = useQuery(SiteSettingsQuery, {
        variables: {siteKey},
        skip: !siteKey,
        fetchPolicy: 'network-only'
    });

    useEffect(() => {
        if (data && data.mfaTotp && data.mfaTotp.siteSettings) {
            setEnabled(Boolean(data.mfaTotp.siteSettings.enabled));
            setEnforced(Boolean(data.mfaTotp.siteSettings.enforced));
        }
    }, [data]);

    const mapError = err => {
        const msg = (err && err.graphQLErrors && err.graphQLErrors[0] && err.graphQLErrors[0].message)
            || (err && err.message)
            || 'unknown_error';
        if (msg.indexOf('permission_denied') !== -1) return 'siteSettings.errors.permissionDenied';
        if (msg.indexOf('not_authenticated') !== -1) return 'siteSettings.errors.notAuthenticated';
        return 'siteSettings.errors.generic';
    };

    const [saveMutation, {loading: saving}] = useMutation(SetSiteSettingsMutation, {
        onCompleted: () => {
            setErrorKey(null);
            setSavedAt(new Date());
        },
        onError: err => setErrorKey(mapError(err))
    });

    const save = () => {
        setSavedAt(null);
        setErrorKey(null);
        saveMutation({variables: {siteKey, enabled, enforced: enabled ? enforced : false}});
    };

    if (!siteKey) {
        return (
            <ContentLayout
                paper
                content={
                    <div style={{padding: '24px'}}>
                        <Typography>{t('siteSettings.noSite')}</Typography>
                    </div>
                }
            />
        );
    }

    const mainActions = [
        <Button key="save"
                size="big"
                color="accent"
                isDisabled={saving || loading}
                data-testid="site-settings-save-btn"
                label={t('siteSettings.save')}
                onClick={save}/>
    ];

    return (
        <ContentLayout
            paper
            header={(
                <div style={{backgroundColor: 'white'}}>
                    <Header title={t('siteSettings.title', {siteKey})}
                            mainActions={mainActions}/>
                </div>
            )}
            content={(
                <div style={{padding: '24px', maxWidth: 720}}>
                    {loading ? (
                        <Loader/>
                    ) : (
                        <>
                            <Typography style={{marginBottom: 24, display: 'block'}}>
                                {t('siteSettings.description')}
                            </Typography>

                            <div style={{marginBottom: 24, display: 'flex', alignItems: 'flex-start', gap: 12}}>
                                <input id="totp-site-enabled"
                                       type="checkbox"
                                       checked={enabled}
                                       data-testid="site-enabled-toggle"
                                       style={{marginTop: 4}}
                                       onChange={e => setEnabled(e.target.checked)}/>
                                <div>
                                    <label htmlFor="totp-site-enabled"
                                           style={{fontWeight: 600, cursor: 'pointer', display: 'block'}}>
                                        {t('siteSettings.enabled.label')}
                                    </label>
                                    <Typography variant="caption" style={{display: 'block', color: '#555'}}>
                                        {t('siteSettings.enabled.help')}
                                    </Typography>
                                </div>
                            </div>

                            <div style={{marginBottom: 24, display: 'flex', alignItems: 'flex-start', gap: 12,
                                opacity: enabled ? 1 : 0.5}}>
                                <input id="totp-site-enforced"
                                       type="checkbox"
                                       checked={enabled && enforced}
                                       disabled={!enabled}
                                       data-testid="site-enforced-toggle"
                                       style={{marginTop: 4}}
                                       onChange={e => setEnforced(e.target.checked)}/>
                                <div>
                                    <label htmlFor="totp-site-enforced"
                                           style={{fontWeight: 600, cursor: enabled ? 'pointer' : 'not-allowed',
                                               display: 'block'}}>
                                        {t('siteSettings.enforced.label')}
                                    </label>
                                    <Typography variant="caption" style={{display: 'block', color: '#555'}}>
                                        {t('siteSettings.enforced.help')}
                                    </Typography>
                                </div>
                            </div>

                            {errorKey && (
                                <Typography style={{color: '#c00', display: 'block', marginTop: 12}}
                                            data-testid="site-settings-error">
                                    {t(errorKey)}
                                </Typography>
                            )}
                            {savedAt && !errorKey && (
                                <Typography style={{color: '#080', display: 'block', marginTop: 12}}
                                            data-testid="site-settings-saved">
                                    {t('siteSettings.saved')}
                                </Typography>
                            )}
                        </>
                    )}
                </div>
            )}
        />
    );
};

export default SiteSettings;
