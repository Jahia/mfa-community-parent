import {registry} from '@jahia/ui-extender';
import i18next from 'i18next';
import register from './MfaExtensions.register';

export default function () {
    registry.add('callback', 'mfa-factors-extensions', {
        targets: ['jahiaApp-init:99'],
        callback: async () => {
            await i18next.loadNamespaces('mfa-factors-extensions');
            register();
            if (process.env.NODE_ENV !== 'production') {
                console.debug('%c mfa-factors-extensions: activation completed', 'color: #006633');
            }
        }
    });
}
