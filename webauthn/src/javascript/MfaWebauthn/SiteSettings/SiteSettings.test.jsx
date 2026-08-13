import React from 'react';
import {describe, it, expect, vi, beforeEach, afterEach} from 'vitest';
import {render, screen, waitFor} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import {MockedProvider} from '@apollo/client/testing';
import SiteSettings from './SiteSettings';
import {SiteSettingsQuery, SetSiteSettingsMutation} from './SiteSettings.gql';

// SiteSettings only needs the presentational shell from moonstone/moonstone-alpha - render small
// native substitutes instead of the real design-system bundle. This keeps the test exercising
// SiteSettings' own data-flow/gating logic rather than moonstone's internals, and keeps it
// decoupled from the (older, React 17/16-pinned) peer deps those two packages still declare.
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

const SITE_KEY = 'mySite';

/** A MockedProvider `mocks` entry that resolves the site settings query with the given settings. */
function querySuccess(settings) {
    return {
        request: {query: SiteSettingsQuery, variables: {siteKey: SITE_KEY}},
        result: {data: {mfaWebauthn: {siteSettings: settings}}}
    };
}

/** A MockedProvider `mocks` entry that fails the site settings query outright (network error). */
function queryFailure() {
    return {
        request: {query: SiteSettingsQuery, variables: {siteKey: SITE_KEY}},
        error: new Error('network down')
    };
}

function renderSiteSettings(mocks) {
    return render(
        <MockedProvider mocks={mocks}>
            <SiteSettings/>
        </MockedProvider>
    );
}

beforeEach(() => {
    window.contextJsParameters = {siteKey: SITE_KEY};
});

afterEach(() => {
    delete window.contextJsParameters;
});

describe('SiteSettings - load failure', () => {
    it('renders a blocking error state and does not render the editable form', async () => {
        renderSiteSettings([queryFailure()]);

        expect(await screen.findByTestId('webauthn-site-settings-load-error')).toBeInTheDocument();

        // The form that would let an admin edit-then-save must not be present: rendering it here
        // would let Save silently persist the component's constructor defaults (enabled: false)
        // over the site's real, currently-saved setting.
        expect(screen.queryByTestId('webauthn-site-enabled-toggle')).not.toBeInTheDocument();
        expect(screen.queryByTestId('webauthn-site-groups-input')).not.toBeInTheDocument();
    });

    it('keeps Save disabled so the wipe-on-error cannot be triggered', async () => {
        renderSiteSettings([queryFailure()]);

        await screen.findByTestId('webauthn-site-settings-load-error');

        expect(screen.getByTestId('webauthn-site-settings-save-btn')).toBeDisabled();
    });
});

describe('SiteSettings - Save gating on load', () => {
    it('disables Save while the query is loading, then enables it once the settings have populated the form', async () => {
        renderSiteSettings([querySuccess({
            siteKey: SITE_KEY,
            enabled: false,
            enabledGroups: []
        })]);

        // Synchronously after the first render, the query is still in flight: Save must not be
        // enabled on the strength of the form's constructor defaults.
        expect(screen.getByTestId('webauthn-site-settings-save-btn')).toBeDisabled();

        await screen.findByTestId('webauthn-site-enabled-toggle');

        await waitFor(() => {
            expect(screen.getByTestId('webauthn-site-settings-save-btn')).toBeEnabled();
        });
    });
});

describe('SiteSettings - successful load', () => {
    it('populates the form fields from the server response', async () => {
        renderSiteSettings([querySuccess({
            siteKey: SITE_KEY,
            enabled: true,
            enabledGroups: ['editors', 'reviewers']
        })]);

        expect(await screen.findByTestId('webauthn-site-enabled-toggle')).toBeChecked();
        expect(screen.getByTestId('webauthn-site-groups-input')).toHaveValue('editors, reviewers');
    });

    it('leaves the checkbox unchecked and the groups field empty when the site has no settings yet', async () => {
        renderSiteSettings([querySuccess({
            siteKey: SITE_KEY,
            enabled: false,
            enabledGroups: []
        })]);

        expect(await screen.findByTestId('webauthn-site-enabled-toggle')).not.toBeChecked();
        expect(screen.getByTestId('webauthn-site-groups-input')).toHaveValue('');
    });
});

describe('SiteSettings - save path', () => {
    it('submits the currently displayed values as mutation variables', async () => {
        const user = userEvent.setup();
        const expectedVariables = {
            siteKey: SITE_KEY,
            enabled: true,
            enabledGroups: ['editors', 'reviewers']
        };
        const saveMock = {
            request: {query: SetSiteSettingsMutation, variables: expectedVariables},
            result: {
                data: {
                    upa: {
                        mfaFactors: {
                            webauthn: {
                                setSiteSettings: {
                                    siteKey: SITE_KEY,
                                    enabled: true,
                                    enabledGroups: ['editors', 'reviewers']
                                }
                            }
                        }
                    }
                }
            }
        };

        renderSiteSettings([
            querySuccess({
                siteKey: SITE_KEY,
                enabled: true,
                enabledGroups: ['editors', 'reviewers']
            }),
            saveMock
        ]);

        await screen.findByTestId('webauthn-site-enabled-toggle');
        await user.click(screen.getByTestId('webauthn-site-settings-save-btn'));

        expect(await screen.findByTestId('webauthn-site-settings-saved')).toBeInTheDocument();
    });

    it('filters blank entries and trims whitespace out of the comma-separated groups field', async () => {
        const user = userEvent.setup();
        const expectedVariables = {
            siteKey: SITE_KEY,
            enabled: true,
            enabledGroups: ['editors', 'reviewers']
        };
        const saveMock = {
            request: {query: SetSiteSettingsMutation, variables: expectedVariables},
            result: {
                data: {
                    upa: {
                        mfaFactors: {
                            webauthn: {
                                setSiteSettings: {
                                    siteKey: SITE_KEY,
                                    enabled: true,
                                    enabledGroups: ['editors', 'reviewers']
                                }
                            }
                        }
                    }
                }
            }
        };

        renderSiteSettings([
            querySuccess({
                siteKey: SITE_KEY,
                enabled: true,
                enabledGroups: []
            }),
            saveMock
        ]);

        await screen.findByTestId('webauthn-site-enabled-toggle');
        await user.clear(screen.getByTestId('webauthn-site-groups-input'));
        await user.type(screen.getByTestId('webauthn-site-groups-input'), ' editors ,, reviewers ,  ');
        await user.click(screen.getByTestId('webauthn-site-settings-save-btn'));

        expect(await screen.findByTestId('webauthn-site-settings-saved')).toBeInTheDocument();
    });

    it('sends an empty enabledGroups list when the site is disabled, even if the field has stale text', async () => {
        const user = userEvent.setup();
        const expectedVariables = {
            siteKey: SITE_KEY,
            enabled: false,
            enabledGroups: []
        };
        const saveMock = {
            request: {query: SetSiteSettingsMutation, variables: expectedVariables},
            result: {
                data: {
                    upa: {
                        mfaFactors: {
                            webauthn: {
                                setSiteSettings: {
                                    siteKey: SITE_KEY,
                                    enabled: false,
                                    enabledGroups: []
                                }
                            }
                        }
                    }
                }
            }
        };

        renderSiteSettings([
            querySuccess({
                siteKey: SITE_KEY,
                enabled: true,
                enabledGroups: ['editors']
            }),
            saveMock
        ]);

        await screen.findByTestId('webauthn-site-enabled-toggle');
        await user.click(screen.getByTestId('webauthn-site-enabled-toggle'));
        await user.click(screen.getByTestId('webauthn-site-settings-save-btn'));

        expect(await screen.findByTestId('webauthn-site-settings-saved')).toBeInTheDocument();
    });

    it('surfaces a mutation error to the admin instead of swallowing it', async () => {
        const user = userEvent.setup();
        const expectedVariables = {
            siteKey: SITE_KEY,
            enabled: false,
            enabledGroups: []
        };
        const failingSaveMock = {
            request: {query: SetSiteSettingsMutation, variables: expectedVariables},
            error: new Error('permission_denied')
        };

        renderSiteSettings([
            querySuccess({
                siteKey: SITE_KEY,
                enabled: false,
                enabledGroups: []
            }),
            failingSaveMock
        ]);

        await screen.findByTestId('webauthn-site-enabled-toggle');
        await user.click(screen.getByTestId('webauthn-site-settings-save-btn'));

        expect(await screen.findByTestId('webauthn-site-settings-error')).toBeInTheDocument();
        expect(screen.queryByTestId('webauthn-site-settings-saved')).not.toBeInTheDocument();
        await waitFor(() => {
            expect(screen.getByTestId('webauthn-site-settings-save-btn')).toBeEnabled();
        });
    });
});
