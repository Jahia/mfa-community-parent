import React from 'react';
import {registry} from '@jahia/ui-extender';
import {GlobalLink, Password, Report, Security} from '@jahia/moonstone';
import MyMfaSettings from './MfaTotpFactor/MyMfaSettings/MyMfaSettings';
import SiteSettings from './MfaTotpFactor/SiteSettings/SiteSettings';
import ExtensionsSettings from './MfaTotpFactor/ExtensionsSettings/ExtensionsSettings';
import AuditReporting from './MfaTotpFactor/AuditReporting/AuditReporting';
import AuditReportSection from './MfaTotpFactor/SiteSettings/AuditReportSection';

// Common guards for every per-site administration entry: site admins only, never on systemsite,
// and ONLY on sites where the MFA modules are actually installed. The shared group/Extensions/Audit
// entries gate on mfa-factors-extensions - the factors jahia-depend on it, so it is present on a
// site exactly when at least one factor (TOTP or WebAuthn) is enabled there. The per-factor
// settings entry overrides this with its own factor module (see below).
const SITE_ADMIN_GUARDS = {
    requiredSitePermission: 'siteAdminAccess',
    isEnabled: siteKey => siteKey !== 'systemsite',
    // jcontent expects a STRING and checks site.installedModulesWithAllDependencies.indexOf(value);
    // an array never matches. The dependency set is included, so gating the shared entries on the
    // extensions module shows them whenever any factor is enabled on the site.
    requireModuleInstalledOnSite: 'mfa-factors-extensions'
};

export default function () {
    if (process.env.NODE_ENV !== 'production') {
        console.debug('%c mfa-factors-totp: activation in progress', 'color: #006633');
    }

    // "MFA Community" group in the user dashboard. Children attach through the
    // 'dashboard-mfa-community-dashboard' target. Registered defensively because the totp and
    // webauthn bundles each may be installed alone - whichever activates first wins.
    if (!registry.get('adminRoute', 'mfa-community-dashboard')) {
        registry.add('adminRoute', 'mfa-community-dashboard', {
            targets: ['dashboard:99.2'],
            icon: <Security/>,
            label: 'mfa-factors-totp:mfaCommunity.menuLabel',
            isSelectable: false
        });
    }

    // MFA Community > Authenticator app (TOTP): enroll / disable / regenerate backup codes.
    registry.add('adminRoute', 'mfa-factors-totp', {
        targets: ['dashboard-mfa-community-dashboard:1'],
        icon: <Password/>,
        label: 'mfa-factors-totp:title',
        isSelectable: true,
        render: () => React.createElement(MyMfaSettings)
    });

    // "MFA Community" group in site administration. Children attach through the
    // 'administration-sites-mfa-community' target. Registered defensively because the totp and
    // webauthn bundles each may be installed alone - whichever activates first wins.
    if (!registry.get('adminRoute', 'mfa-community')) {
        registry.add('adminRoute', 'mfa-community', {
            targets: ['administration-sites:90'],
            icon: <Security/>,
            label: 'mfa-factors-totp:mfaCommunity.menuLabel',
            isSelectable: false,
            ...SITE_ADMIN_GUARDS
        });
    }

    // MFA Community > Extensions: the shared login/logout routing (per-site URLs consumed by the
    // mfa-factors-extensions login provider). Lives in this bundle because the URLs are stored on
    // the upaTotp:siteSettings mixin and managed through the totp GraphQL API.
    registry.add('adminRoute', 'mfa-community-extensions', {
        targets: ['administration-sites-mfa-community:1'],
        icon: <GlobalLink/>,
        label: 'mfa-factors-totp:extensionsSettings.menuLabel',
        isSelectable: true,
        ...SITE_ADMIN_GUARDS,
        render: () => React.createElement(ExtensionsSettings)
    });

    // MFA Community > Authenticator app (TOTP): per-site TOTP policy (enable/enforce/grace/groups).
    registry.add('adminRoute', 'mfa-factors-totp-site-settings', {
        targets: ['administration-sites-mfa-community:2'],
        icon: <Password/>,
        label: 'mfa-factors-totp:siteSettings.menuLabel',
        isSelectable: true,
        ...SITE_ADMIN_GUARDS,
        // This page is TOTP-specific: show it only where the TOTP factor itself is enabled.
        requireModuleInstalledOnSite: 'mfa-factors-totp',
        render: () => React.createElement(SiteSettings)
    });

    // MFA Community > Audit & reporting: one page composing every factor's audit/report section
    // (registered below under the 'mfa-community-audit-section' type). Guarded like the group.
    if (!registry.get('adminRoute', 'mfa-community-audit')) {
        registry.add('adminRoute', 'mfa-community-audit', {
            targets: ['administration-sites-mfa-community:4'],
            icon: <Report/>,
            label: 'mfa-factors-totp:auditReporting.menuLabel',
            isSelectable: true,
            ...SITE_ADMIN_GUARDS,
            render: () => React.createElement(AuditReporting)
        });
    }

    // TOTP's contribution to the shared Audit & reporting page.
    registry.add('mfa-community-audit-section', 'mfa-factors-totp', {
        priority: 1,
        component: AuditReportSection
    });
}
