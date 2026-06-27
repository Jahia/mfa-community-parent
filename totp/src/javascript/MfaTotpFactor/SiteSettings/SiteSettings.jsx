import React, {useEffect, useState} from 'react';
import {useTranslation} from 'react-i18next';
import {useQuery, useMutation} from '@apollo/client';
import {Button, Header, Typography, Loader} from '@jahia/moonstone';
import {ContentLayout} from '@jahia/moonstone-alpha';
import {SiteSettingsQuery, SetSiteSettingsMutation} from './SiteSettings.gql';
import {mapAdminError, resolveSiteKey} from './siteSettings.util';
import ResetUserSection from './ResetUserSection';

// Moonstone's CSS reset can drop the native focus ring on raw <input> elements. This module's
// webpack only loads .scss (no plain .css loader), so the focus-visible rule is injected via a
// plain <style> element instead of a CSS module. Restores a high-contrast WCAG 2.2 focus ring.
const ADMIN_INPUT_FOCUS_STYLE = '.mfa-admin-input:focus-visible{outline:2px solid #00538b;outline-offset:2px;}';

const SiteSettings = () => {
    const {t} = useTranslation('mfa-factors-totp');
    const siteKey = resolveSiteKey();

    const [enabled, setEnabled] = useState(false);
    const [groups, setGroups] = useState('');
    // Login/logout URLs are edited on the "MFA Community > Extensions" page. This page no longer
    // sends them on save: the backend treats omitted URLs as "keep", so omitting them avoids
    // clobbering the URLs the Extensions page owns.
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
            setEnabled(Boolean(s.enabled));
            setGroups((s.enabledGroups || []).join(', '));
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
        const groupList = groups.split(',').map(g => g.trim()).filter(Boolean);
        saveMutation({
            variables: {
                siteKey,
                enabled,
                enabledGroups: enabled ? groupList : []
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
                data-testid="site-settings-save-btn"
                label={saving ? t('siteSettings.saving') : t('siteSettings.save')}
                onClick={save}/>
    ];

    return (
        <ContentLayout
            paper
            header={(
                <div style={{backgroundColor: 'white'}}>
                    <Header title={t('siteSettings.title', {siteKey})} mainActions={mainActions}/>
                </div>
            )}
            content={(
                <div style={{padding: '24px', maxWidth: 760}}>
                    <style>{ADMIN_INPUT_FOCUS_STYLE}</style>
                    {loading ? <Loader/> : (
                        <>
                            <Typography style={{marginBottom: 24, display: 'block'}}>
                                {t('siteSettings.description')}
                            </Typography>

                            <CheckboxField id="totp-site-enabled"
                                           testid="site-enabled-toggle"
                                           checked={enabled}
                                           label={t('siteSettings.enabled.label')}
                                           help={t('siteSettings.enabled.help')}
                                           onChange={setEnabled}/>

                            <TextField id="totp-site-groups"
                                       testid="site-groups-input"
                                       type="text"
                                       value={groups}
                                       disabled={!enabled}
                                       placeholder="editors, reviewers"
                                       label={t('siteSettings.groups.label')}
                                       help={t('siteSettings.groups.help')}
                                       onChange={v => setGroups(v)}/>

                            {errorKey && (
                                <Typography role="alert"
                                            style={{color: '#a00000', display: 'block', marginTop: 12}}
                                            data-testid="site-settings-error"
                                >
                                    {t(errorKey)}
                                </Typography>
                            )}
                            {savedAt && !errorKey && (
                                <Typography role="status"
                                            aria-live="polite"
                                            style={{color: '#006600', display: 'block', marginTop: 12}}
                                            data-testid="site-settings-saved"
                                >
                                    {t('siteSettings.saved')}
                                </Typography>
                            )}

                            <hr style={{margin: '32px 0'}}/>
                            <ResetUserSection siteKey={siteKey}/>
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
const CheckboxField = ({id, testid, checked, disabled, label, help, onChange}) => (
    <div style={{marginBottom: 24, display: 'flex', alignItems: 'flex-start', gap: 12}}>
        <input id={id}
               type="checkbox"
               checked={checked}
               disabled={disabled}
               data-testid={testid}
               aria-describedby={`${id}-help`}
               className="mfa-admin-input"
               style={{marginTop: 4, cursor: disabled ? 'not-allowed' : 'pointer'}}
               onChange={e => onChange(e.target.checked)}/>
        <div>
            <label htmlFor={id} style={{fontWeight: 600, display: 'block', color: disabled ? '#767676' : 'inherit', cursor: disabled ? 'not-allowed' : 'pointer'}}>
                {label}
            </label>
            <Typography id={`${id}-help`} variant="caption" style={{display: 'block', color: '#555'}}>{help}</Typography>
        </div>
    </div>
);

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

export default SiteSettings;
