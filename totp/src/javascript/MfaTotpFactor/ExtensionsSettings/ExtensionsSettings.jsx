import React, {useEffect, useState} from 'react';
import {useTranslation} from 'react-i18next';
import {useQuery, useMutation} from '@apollo/client';
import {Button, Header, Typography, Loader} from '@jahia/moonstone';
import {ContentLayout} from '@jahia/moonstone-alpha';
import {SiteSettingsQuery, SetSiteSettingsMutation} from '../SiteSettings/SiteSettings.gql';
import {mapAdminError, resolveSiteKey} from '../SiteSettings/siteSettings.util';

// Moonstone's CSS reset can drop the native focus ring on raw <input> elements. This module's
// webpack only loads .scss (no plain .css loader), so the focus-visible rule is injected via a
// plain <style> element instead of a CSS module. Restores a high-contrast WCAG 2.2 focus ring.
const ADMIN_INPUT_FOCUS_STYLE = '.mfa-admin-input:focus-visible{outline:2px solid #00538b;outline-offset:2px;}';

/**
 * "MFA Community > Extensions" administration page: the per-site login/logout routing consumed
 * by the shared MfaLoginLogoutProvider (mfa-factors-extensions bundle). Only the two URLs are
 * editable here - the TOTP policy fields loaded alongside them are passed back unchanged on
 * save, because the GraphQL mutation persists the full upaTotp:siteSettings state.
 */
const ExtensionsSettings = () => {
    const {t} = useTranslation('mfa-factors-totp');
    const siteKey = resolveSiteKey();

    const [loginUrl, setLoginUrl] = useState('');
    const [logoutUrl, setLogoutUrl] = useState('');
    // Policy snapshot (not edited here): round-tripped so saving URLs never alters the policy.
    const [policy, setPolicy] = useState({enabled: false, enabledGroups: []});
    const [savedAt, setSavedAt] = useState(null);
    const [errorKey, setErrorKey] = useState(null);

    const {data, loading} = useQuery(SiteSettingsQuery, {
        variables: {siteKey},
        skip: !siteKey,
        fetchPolicy: 'network-only'
    });

    useEffect(() => {
        const s = data && data.mfaTotp && data.mfaTotp.siteSettings;
        if (s) {
            setLoginUrl(s.loginUrl || '');
            setLogoutUrl(s.logoutUrl || '');
            setPolicy({
                enabled: Boolean(s.enabled),
                enabledGroups: s.enabledGroups || []
            });
        }
    }, [data]);

    const [saveMutation, {loading: saving}] = useMutation(SetSiteSettingsMutation, {
        onCompleted: () => {
            setErrorKey(null);
            setSavedAt(Date.now());
        },
        onError: err => setErrorKey(mapAdminError(err))
    });

    const save = () => {
        setSavedAt(null);
        setErrorKey(null);
        saveMutation({
            variables: {
                siteKey,
                enabled: policy.enabled,
                enabledGroups: policy.enabledGroups,
                // Send "" to clear and a path to set; never null/undefined, which the backend
                // would treat as "keep" instead of an explicit clear.
                loginUrl: loginUrl.trim(),
                logoutUrl: logoutUrl.trim()
            }
        });
    };

    if (!siteKey) {
        return (
            <ContentLayout paper
                           content={
                               <div style={{padding: '24px'}}>
                                   <Typography>{t('siteSettings.noSite')}</Typography>
                               </div>
            }/>
        );
    }

    const mainActions = [
        <Button key="save"
                size="big"
                color="accent"
                isDisabled={saving || loading}
                data-testid="extensions-settings-save-btn"
                label={saving ? t('siteSettings.saving') : t('siteSettings.save')}
                onClick={save}/>
    ];

    return (
        <ContentLayout
            paper
            header={(
                <div style={{backgroundColor: 'white'}}>
                    <Header title={t('extensionsSettings.title', {siteKey})} mainActions={mainActions}/>
                </div>
            )}
            content={(
                <div style={{padding: '24px', maxWidth: 760}}>
                    <style>{ADMIN_INPUT_FOCUS_STYLE}</style>
                    {loading ? <Loader/> : (
                        <>
                            <Typography style={{marginBottom: 24, display: 'block'}}>
                                {t('extensionsSettings.description')}
                            </Typography>

                            <TextField id="totp-site-login-url"
                                       testid="site-login-url-input"
                                       type="text"
                                       value={loginUrl}
                                       placeholder="/sites/mySite/login.html"
                                       label={t('extensionsSettings.loginUrl.label')}
                                       help={t('extensionsSettings.loginUrl.help')}
                                       onChange={v => setLoginUrl(v)}/>

                            <TextField id="totp-site-logout-url"
                                       testid="site-logout-url-input"
                                       type="text"
                                       value={logoutUrl}
                                       placeholder="/sites/mySite/logout.html"
                                       label={t('extensionsSettings.logoutUrl.label')}
                                       help={t('extensionsSettings.logoutUrl.help')}
                                       onChange={v => setLogoutUrl(v)}/>

                            {errorKey && (
                                <Typography role="alert"
                                            style={{color: '#a00000', display: 'block', marginTop: 12}}
                                            data-testid="extensions-settings-error"
                                >
                                    {t(errorKey)}
                                </Typography>
                            )}
                            {savedAt && !errorKey && (
                                <Typography role="status"
                                            aria-live="polite"
                                            style={{color: '#006600', display: 'block', marginTop: 12}}
                                            data-testid="extensions-settings-saved"
                                >
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

// Disabled fields are greyed via the control (cursor + #767676 label) rather than a wrapper
// opacity, so the help text keeps its #555 colour (7.46:1 on white) and the label stays at
// #767676 (4.54:1) - both above the WCAG AA/AAA threshold even when disabled.
const TextField = ({id, testid, type, value, disabled, placeholder, label, help, min, max, onChange}) => (
    <div style={{marginBottom: 24}}>
        <label htmlFor={id} style={{fontWeight: 600, display: 'block', marginBottom: 4, color: disabled ? '#767676' : 'inherit'}}>{label}</label>
        <input id={id}
               type={type}
               value={value}
               disabled={disabled}
               placeholder={placeholder}
               min={min}
               max={max}
               data-testid={testid}
               aria-describedby={`${id}-help`}
               className="mfa-admin-input"
               style={{padding: '0.4rem', minWidth: 280, minHeight: 44, boxSizing: 'border-box',
                       borderRadius: 4, border: '1px solid #767676',
                       cursor: disabled ? 'not-allowed' : 'auto'}}
               onChange={e => onChange(e.target.value)}/>
        <Typography id={`${id}-help`} variant="caption" style={{display: 'block', color: '#555', marginTop: 4}}>{help}</Typography>
    </div>
);

export default ExtensionsSettings;
