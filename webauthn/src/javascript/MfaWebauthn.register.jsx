import React from 'react';
import {registry} from '@jahia/ui-extender';
import {Key, Report, Security} from '@jahia/moonstone';
import MyWebauthnSettings from './MfaWebauthn/MyWebauthnSettings/MyWebauthnSettings';
import SiteSettings from './MfaWebauthn/SiteSettings/SiteSettings';
import AuditReporting from './MfaWebauthn/AuditReporting/AuditReporting';
import AuditReportSection from './MfaWebauthn/SiteSettings/AuditReportSection';

// Common guards for every per-site administration entry: site admins only, never on systemsite,
// and ONLY on sites where the MFA modules are actually installed. The shared group/Audit entries
// gate on mfa-factors-extensions - the factors jahia-depend on it, so it is present on a site
// exactly when at least one factor (TOTP or WebAuthn) is enabled there. The per-factor settings
// entry overrides this with its own factor module (see below).
const SITE_ADMIN_GUARDS = {
    requiredSitePermission: 'siteAdminAccess',
    isEnabled: siteKey => siteKey !== 'systemsite',
    // Jcontent expects a STRING and checks site.installedModulesWithAllDependencies.indexOf(value);
    // an array never matches. The dependency set is included, so gating the shared entries on the
    // extensions module shows them whenever any factor is enabled on the site.
    requireModuleInstalledOnSite: 'mfa-factors-extensions'
};

export default function () {
    if (process.env.NODE_ENV !== 'production') {
        console.debug('%c mfa-factors-webauthn: activation in progress', 'color: #006633');
    }

    // "MFA Community" group in the user dashboard. Children attach through the
    // 'dashboard-mfa-community-dashboard' target. Registered defensively because the totp and
    // webauthn bundles each may be installed alone - whichever activates first wins.
    if (!registry.get('adminRoute', 'mfa-community-dashboard')) {
        registry.add('adminRoute', 'mfa-community-dashboard', {
            targets: ['dashboard:99.2'],
            icon: <Security/>,
            label: 'mfa-factors-webauthn:mfaCommunity.menuLabel',
            isSelectable: false
        });
    }

    // MFA Community > Security keys and passkeys: register / rename / remove passkeys.
    registry.add('adminRoute', 'mfa-factors-webauthn', {
        targets: ['dashboard-mfa-community-dashboard:2'],
        icon: <Key/>,
        label: 'mfa-factors-webauthn:title',
        isSelectable: true,
        render: () => React.createElement(MyWebauthnSettings)
    });

    // "MFA Community" group in site administration. Children attach through the
    // 'administration-sites-mfa-community' target. Registered defensively because the totp and
    // webauthn bundles each may be installed alone - whichever activates first wins.
    if (!registry.get('adminRoute', 'mfa-community')) {
        registry.add('adminRoute', 'mfa-community', {
            targets: ['administration-sites:90'],
            icon: <Security/>,
            label: 'mfa-factors-webauthn:mfaCommunity.menuLabel',
            isSelectable: false,
            ...SITE_ADMIN_GUARDS
        });
    }

    // MFA Community > Security keys & passkeys: per-site WebAuthn policy (enable/enforce/grace/groups).
    registry.add('adminRoute', 'mfa-factors-webauthn-site-settings', {
        targets: ['administration-sites-mfa-community:3'],
        icon: <Key/>,
        label: 'mfa-factors-webauthn:siteSettings.menuLabel',
        isSelectable: true,
        ...SITE_ADMIN_GUARDS,
        // This page is WebAuthn-specific: show it only where the WebAuthn factor itself is enabled.
        requireModuleInstalledOnSite: 'mfa-factors-webauthn',
        render: () => React.createElement(SiteSettings)
    });

    // MFA Community > Audit & reporting: one page composing every factor's audit/report section
    // (registered below under the 'mfa-community-audit-section' type). Guarded like the group.
    if (!registry.get('adminRoute', 'mfa-community-audit')) {
        registry.add('adminRoute', 'mfa-community-audit', {
            targets: ['administration-sites-mfa-community:4'],
            icon: <Report/>,
            label: 'mfa-factors-webauthn:auditReporting.menuLabel',
            isSelectable: true,
            ...SITE_ADMIN_GUARDS,
            render: () => React.createElement(AuditReporting)
        });
    }

    // WebAuthn's contribution to the shared Audit & reporting page.
    registry.add('mfa-community-audit-section', 'mfa-factors-webauthn', {
        priority: 2,
        component: AuditReportSection
    });
}
