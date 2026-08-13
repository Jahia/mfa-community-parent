import React from 'react';
import {describe, it, expect, vi} from 'vitest';
import {render, screen, waitFor} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import {MockedProvider} from '@apollo/client/testing';
import GlobalSettings from './GlobalSettings';
import {ConfigurationQuery, SaveConfigurationMutation} from './GlobalSettings.gql';

// GlobalSettings only needs the presentational shell from moonstone/moonstone-alpha - render
// small native substitutes instead of the real design-system bundle. This keeps the test
// exercising GlobalSettings' own data-flow/gating logic rather than moonstone's internals, and
// keeps it decoupled from the (older, React 18/17-pinned) peer deps those two packages still
// declare - see the "incorrect peer dependency" warnings from `yarn add`.
vi.mock('@jahia/moonstone', () => ({
    Button: ({label, onClick, isDisabled, ...props}) => (
        <button type="button" disabled={isDisabled} onClick={onClick} {...props}>{label}</button>
    ),
    Header: ({title, mainActions}) => (
        <div>
            <h1>{title}</h1>
            {mainActions}
        </div>
    ),
    Typography: ({children, ...props}) => <span {...props}>{children}</span>,
    Loader: () => <div data-testid="loader">loading</div>
}));

vi.mock('@jahia/moonstone-alpha', () => ({
    ContentLayout: ({header, content}) => <div>{header}{content}</div>
}));

const baseConfig = {
    __typename: 'MfaExtensionsConfiguration',
    enforcedFactors: [],
    graceDays: 0,
    loginGateEnabled: false,
    loginGateTrustForwardedFor: false,
    loginGateIpWhitelist: '',
    loginUrl: '',
    logoutUrl: '',
    resetNotifyEmail: '',
    registeredFactors: ['totp', 'webauthn']
};

/** A MockedProvider `mocks` entry that resolves the configuration query with the given config. */
function querySuccess(config = baseConfig) {
    return {
        request: {query: ConfigurationQuery},
        result: {data: {mfaExtensionsConfiguration: config}}
    };
}

/** A MockedProvider `mocks` entry that fails the configuration query outright (network error). */
function queryFailure() {
    return {
        request: {query: ConfigurationQuery},
        error: new Error('network down')
    };
}

function renderSettings(mocks) {
    return render(
        <MockedProvider mocks={mocks}>
            <GlobalSettings/>
        </MockedProvider>
    );
}

describe('GlobalSettings - load failure', () => {
    it('renders a blocking error state and does not render the editable form', async () => {
        renderSettings([queryFailure()]);

        expect(await screen.findByTestId('extensions-global-load-error')).toBeInTheDocument();

        // The form that would let an admin edit-then-save must not be present: rendering it here
        // would let Save silently persist the component's constructor defaults over the real
        // platform configuration.
        expect(screen.queryByTestId('extensions-login-url-input')).not.toBeInTheDocument();
        expect(screen.queryByTestId('extensions-gate-toggle')).not.toBeInTheDocument();
    });

    it('keeps Save disabled so the wipe-on-error cannot be triggered', async () => {
        renderSettings([queryFailure()]);

        await screen.findByTestId('extensions-global-load-error');

        expect(screen.getByTestId('extensions-global-save-btn')).toBeDisabled();
    });
});

describe('GlobalSettings - Save gating on load', () => {
    it('disables Save while the query is loading, then enables it once the config has populated the form', async () => {
        renderSettings([querySuccess()]);

        // Synchronously after the first render, the query is still in flight: Save must not be
        // enabled on the strength of the form's constructor defaults.
        expect(screen.getByTestId('extensions-global-save-btn')).toBeDisabled();

        // Wait for the populate effect (configLoaded becomes true) rather than just "loading
        // finished", since those are two different flags.
        await screen.findByTestId('extensions-login-url-input');

        await waitFor(() => {
            expect(screen.getByTestId('extensions-global-save-btn')).toBeEnabled();
        });
    });
});

describe('GlobalSettings - successful load', () => {
    it('populates the form fields from the server response', async () => {
        const config = {
            ...baseConfig,
            enforcedFactors: ['totp'],
            graceDays: 14,
            loginGateEnabled: true,
            loginGateIpWhitelist: '10.0.0.0/8',
            loginUrl: '/sites/mySite/login.html',
            logoutUrl: '/sites/mySite/logout.html',
            resetNotifyEmail: 'security@example.com'
        };
        renderSettings([querySuccess(config)]);

        expect(await screen.findByTestId('enforce-totp-toggle')).toBeChecked();
        expect(screen.getByTestId('enforce-webauthn-toggle')).not.toBeChecked();
        expect(screen.getByTestId('extensions-grace-input')).toHaveValue(14);
        expect(screen.getByTestId('extensions-gate-toggle')).toBeChecked();
        expect(screen.getByTestId('extensions-gate-whitelist-input')).toHaveValue('10.0.0.0/8');
        expect(screen.getByTestId('extensions-login-url-input')).toHaveValue('/sites/mySite/login.html');
        expect(screen.getByTestId('extensions-logout-url-input')).toHaveValue('/sites/mySite/logout.html');
        expect(screen.getByTestId('extensions-reset-notify-email-input')).toHaveValue('security@example.com');
    });

    it('defaults trustForwardedFor to false when the field is absent from the response (SEC-135)', async () => {
        // A field genuinely "absent" from a GraphQL/JSON response is a missing key, not a
        // literal `undefined` value (which isn't valid JSON) - so build the config without it.
        const {loginGateTrustForwardedFor: _omit, ...configWithoutTrustForwardedFor} = baseConfig;
        renderSettings([querySuccess(configWithoutTrustForwardedFor)]);

        expect(await screen.findByTestId('extensions-gate-trust-xff-toggle')).not.toBeChecked();
    });

    it('defaults trustForwardedFor to false when the server value is explicitly null (SEC-135)', async () => {
        renderSettings([querySuccess({...baseConfig, loginGateTrustForwardedFor: null})]);

        expect(await screen.findByTestId('extensions-gate-trust-xff-toggle')).not.toBeChecked();
    });

    it('reflects an explicit true from the server as checked (control: the default is not just hardcoded off)', async () => {
        renderSettings([querySuccess({...baseConfig, loginGateTrustForwardedFor: true})]);

        expect(await screen.findByTestId('extensions-gate-trust-xff-toggle')).toBeChecked();
    });
});

describe('GlobalSettings - save path', () => {
    it('submits the currently displayed values as mutation variables', async () => {
        const user = userEvent.setup();
        const expectedVariables = {
            enforcedFactors: ['totp'],
            graceDays: 0,
            loginGateEnabled: false,
            loginGateTrustForwardedFor: false,
            loginGateIpWhitelist: '',
            loginUrl: '',
            logoutUrl: '',
            resetNotifyEmail: ''
        };
        const saveMock = {
            request: {query: SaveConfigurationMutation, variables: expectedVariables},
            result: {data: {mfaExtensionsSaveConfiguration: {...baseConfig, ...expectedVariables}}}
        };

        renderSettings([querySuccess(), saveMock]);

        await screen.findByTestId('extensions-login-url-input');
        await user.click(screen.getByTestId('enforce-totp-toggle'));
        await user.click(screen.getByTestId('extensions-global-save-btn'));

        expect(await screen.findByTestId('extensions-global-saved')).toBeInTheDocument();
    });

    it('surfaces a mutation error to the admin instead of swallowing it', async () => {
        const user = userEvent.setup();
        const expectedVariables = {
            enforcedFactors: [],
            graceDays: 0,
            loginGateEnabled: false,
            loginGateTrustForwardedFor: false,
            loginGateIpWhitelist: '',
            loginUrl: '',
            logoutUrl: '',
            resetNotifyEmail: ''
        };
        const failingSaveMock = {
            request: {query: SaveConfigurationMutation, variables: expectedVariables},
            error: new Error('Permission denied')
        };

        renderSettings([querySuccess(), failingSaveMock]);

        await screen.findByTestId('extensions-login-url-input');
        await user.click(screen.getByTestId('extensions-global-save-btn'));

        expect(await screen.findByTestId('extensions-global-error')).toBeInTheDocument();
        expect(screen.queryByTestId('extensions-global-saved')).not.toBeInTheDocument();
        // Save must re-enable after a failed attempt so the admin can retry.
        await waitFor(() => {
            expect(screen.getByTestId('extensions-global-save-btn')).toBeEnabled();
        });
    });
});
