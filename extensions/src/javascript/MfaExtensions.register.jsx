import React from 'react';
import {registry} from '@jahia/ui-extender';
import {Setting} from '@jahia/moonstone';
import GlobalSettings from './MfaExtensions/GlobalSettings';

export default function () {
    if (process.env.NODE_ENV !== 'production') {
        console.debug('%c mfa-factors-extensions: activation in progress', 'color: #006633');
    }

    // Server administration entry: the platform-wide MFA configuration (PID
    // org.jahia.modules.mfa.extensions) - enforcement policy, /cms/login gate, global
    // login/logout routing. Server administrators only.
    registry.add('adminRoute', 'mfa-extensions-settings', {
        targets: ['administration-server-configuration:30'],
        requiredPermission: 'admin',
        icon: <Setting/>,
        label: 'mfa-factors-extensions:settings.menuLabel',
        isSelectable: true,
        render: () => React.createElement(GlobalSettings)
    });
}
