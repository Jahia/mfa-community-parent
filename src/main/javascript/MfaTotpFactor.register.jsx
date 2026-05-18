import React from 'react';
import {registry} from '@jahia/ui-extender';
import {Shield} from '@jahia/moonstone';
import MyMfaSettings from './MfaTotpFactor/MyMfaSettings/MyMfaSettings';

export default function () {
    registry.add('adminRoute', 'mfa-totp-factor', {
        targets: ['dashboard:99.2'],
        icon: <Shield/>,
        label: 'mfa-totp-factor:title',
        isSelectable: true,
        render: () => <MyMfaSettings/>
    });
}
