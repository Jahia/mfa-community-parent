import React from 'react';
import {useTranslation} from 'react-i18next';
import {registry} from '@jahia/ui-extender';
import {Header, Typography} from '@jahia/moonstone';
import {ContentLayout} from '@jahia/moonstone-alpha';
import {resolveSiteKey} from '../SiteSettings/siteSettings.util';

/**
 * "MFA Community > Audit & reporting" administration page.
 *
 * The page itself owns no content: each factor bundle registers its audit/report table under the
 * 'mfa-community-audit-section' registry type ({priority, component}), and this page renders all
 * of them ordered by priority. The adminRoute for this page is registered defensively by every
 * factor bundle (first one wins), so the page exists for any combination of installed factors and
 * always shows exactly the sections of the factors that are present.
 */
const AuditReporting = () => {
    const {t} = useTranslation('mfa-factors-totp');
    const siteKey = resolveSiteKey();

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

    const sections = registry.find({type: 'mfa-community-audit-section'})
        .slice()
        .sort((a, b) => (a.priority || 0) - (b.priority || 0));

    return (
        <ContentLayout
            paper
            header={(
                <div style={{backgroundColor: 'white'}}>
                    <Header title={t('auditReporting.title', {siteKey})}/>
                </div>
            )}
            content={(
                <div style={{padding: '24px', maxWidth: 760}}>
                    {sections.map((section, index) => (
                        <React.Fragment key={section.key}>
                            {index > 0 && <hr style={{margin: '32px 0'}}/>}
                            {React.createElement(section.component, {siteKey})}
                        </React.Fragment>
                    ))}
                </div>
            )}
        />
    );
};

export default AuditReporting;
