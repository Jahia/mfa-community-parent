import React from 'react';
import {describe, it, expect, vi, afterEach} from 'vitest';
import {render, screen, waitFor} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import {MockedProvider} from '@apollo/client/testing';
import RegisterDialog from './RegisterDialog';
import {StartRegistrationMutation, FinishRegistrationMutation} from '../MfaWebauthn.gql';
import {createCredential, isWebauthnSupported} from '../webauthnBrowser';

// RegisterDialog only needs the presentational shell from moonstone - render small native
// substitutes instead of the real design-system bundle, same rationale as the other admin
// screens' tests. Modal renders its children unconditionally while isOpen so tests can interact
// with the form (the real component already guards `if (!isOpen) return null` before reaching it).
vi.mock('@jahia/moonstone', () => ({
    Button: ({label, onClick, isDisabled, ...props}) => (
        <button type="button" disabled={isDisabled} onClick={onClick} {...props}>{label}</button>
    ),
    Typography: ({children, ...props}) => <span {...props}>{children}</span>,
    Input: ({value, onChange, ...props}) => <input value={value} onChange={onChange} {...props}/>,
    Modal: ({isOpen, children}) => (isOpen ? <div role="dialog">{children}</div> : null),
    ModalHeader: ({title}) => <h2>{title}</h2>,
    ModalBody: ({children}) => <div>{children}</div>,
    ModalFooter: ({children}) => <div>{children}</div>
}));

// The actual WebAuthn ceremony (navigator.credentials.create + base64url<->ArrayBuffer
// conversion) is a browser API boundary this component just calls through to - it is unit-tested
// on its own in webauthnBrowser.test.js. Stubbing it here keeps this test focused on
// RegisterDialog's own orchestration (busy state, nickname handling, error mapping) rather than
// re-proving the ceremony plumbing.
vi.mock('../webauthnBrowser', () => ({
    createCredential: vi.fn(),
    isWebauthnSupported: vi.fn()
}));

const START_MOCK = {
    request: {query: StartRegistrationMutation},
    result: {
        data: {
            upa: {
                mfaFactors: {
                    webauthn: {
                        startRegistration: {publicKeyCredentialCreationOptions: '{"publicKey":{}}'}
                    }
                }
            }
        }
    }
};

function finishMock(nickname) {
    return {
        request: {query: FinishRegistrationMutation, variables: {response: '{"id":"cred-1"}', nickname}},
        result: {
            data: {
                upa: {
                    mfaFactors: {
                        webauthn: {
                            finishRegistration: {
                                registered: true,
                                credentials: [{credentialId: 'cred-1', nickname, signCount: 0, createdAt: '0', lastUsedAt: null, transports: []}]
                            }
                        }
                    }
                }
            }
        }
    };
}

function renderDialog(mocks, props = {}) {
    return render(
        <MockedProvider mocks={mocks}>
            <RegisterDialog isOpen onClose={vi.fn()} onRegistered={vi.fn()} {...props}/>
        </MockedProvider>
    );
}

afterEach(() => {
    vi.resetAllMocks();
});

describe('RegisterDialog - unsupported browser', () => {
    it('shows the unsupported message and disables the confirm button', () => {
        isWebauthnSupported.mockReturnValue(false);
        renderDialog([]);

        expect(screen.getByTestId('webauthn-unsupported')).toBeInTheDocument();
        expect(screen.queryByTestId('webauthn-nickname-input')).not.toBeInTheDocument();
        expect(screen.getByTestId('webauthn-register-confirm')).toBeDisabled();
    });
});

describe('RegisterDialog - nickname field', () => {
    it('lets the admin type a nickname and submits it trimmed', async () => {
        isWebauthnSupported.mockReturnValue(true);
        createCredential.mockResolvedValue('{"id":"cred-1"}');
        const onRegistered = vi.fn();
        const user = userEvent.setup();

        renderDialog([START_MOCK, finishMock('YubiKey')], {onRegistered});

        await user.type(screen.getByTestId('webauthn-nickname-input'), '  YubiKey  ');
        await user.click(screen.getByTestId('webauthn-register-confirm'));

        await waitFor(() => expect(onRegistered).toHaveBeenCalledTimes(1));
        expect(createCredential).toHaveBeenCalledWith('{"publicKey":{}}');
    });

    it('submits a null nickname when the admin leaves it blank', async () => {
        isWebauthnSupported.mockReturnValue(true);
        createCredential.mockResolvedValue('{"id":"cred-1"}');
        const onRegistered = vi.fn();
        const user = userEvent.setup();

        renderDialog([START_MOCK, finishMock(null)], {onRegistered});

        await user.click(screen.getByTestId('webauthn-register-confirm'));

        await waitFor(() => expect(onRegistered).toHaveBeenCalledTimes(1));
    });
});

describe('RegisterDialog - in-flight state', () => {
    it('shows the in-progress label and disables Cancel/Confirm while the ceremony is running', async () => {
        isWebauthnSupported.mockReturnValue(true);
        let resolveCeremony;
        createCredential.mockReturnValue(new Promise(resolve => {
            resolveCeremony = resolve;
        }));
        const user = userEvent.setup();

        renderDialog([START_MOCK, finishMock(null)]);

        await user.click(screen.getByTestId('webauthn-register-confirm'));

        await waitFor(() => {
            expect(screen.getByTestId('webauthn-register-confirm')).toHaveTextContent('register.inProgress');
        });
        expect(screen.getByTestId('webauthn-register-confirm')).toBeDisabled();
        expect(screen.getByText('cancel')).toBeDisabled();

        resolveCeremony('{"id":"cred-1"}');
    });
});

describe('RegisterDialog - error paths', () => {
    it('maps a cancelled/timed-out ceremony (NotAllowedError) to the cancelled error message', async () => {
        isWebauthnSupported.mockReturnValue(true);
        const notAllowed = new Error('timed out');
        notAllowed.name = 'NotAllowedError';
        createCredential.mockRejectedValue(notAllowed);
        const user = userEvent.setup();

        renderDialog([START_MOCK]);

        await user.click(screen.getByTestId('webauthn-register-confirm'));

        expect(await screen.findByTestId('webauthn-register-error')).toHaveTextContent('errors.cancelled');
    });

    it('maps any other ceremony failure to the generic failed error message', async () => {
        isWebauthnSupported.mockReturnValue(true);
        createCredential.mockRejectedValue(new Error('boom'));
        const user = userEvent.setup();

        renderDialog([START_MOCK]);

        await user.click(screen.getByTestId('webauthn-register-confirm'));

        expect(await screen.findByTestId('webauthn-register-error')).toHaveTextContent('errors.failed');
    });

    it('surfaces the generic failed error when the server returns no creation options', async () => {
        isWebauthnSupported.mockReturnValue(true);
        const noOptionsMock = {
            request: {query: StartRegistrationMutation},
            result: {
                data: {
                    upa: {mfaFactors: {webauthn: {startRegistration: {publicKeyCredentialCreationOptions: null}}}}
                }
            }
        };
        const user = userEvent.setup();

        renderDialog([noOptionsMock]);

        await user.click(screen.getByTestId('webauthn-register-confirm'));

        expect(await screen.findByTestId('webauthn-register-error')).toHaveTextContent('errors.failed');
        expect(createCredential).not.toHaveBeenCalled();
    });
});

describe('RegisterDialog - dismissal', () => {
    it('lets the admin cancel without registering anything', async () => {
        isWebauthnSupported.mockReturnValue(true);
        const onClose = vi.fn();
        const user = userEvent.setup();

        renderDialog([], {onClose});
        await user.click(screen.getByText('cancel'));

        expect(onClose).toHaveBeenCalledTimes(1);
        expect(createCredential).not.toHaveBeenCalled();
    });

    it('renders nothing when closed', () => {
        isWebauthnSupported.mockReturnValue(true);
        render(
            <MockedProvider mocks={[]}>
                <RegisterDialog isOpen={false} onClose={vi.fn()} onRegistered={vi.fn()}/>
            </MockedProvider>
        );

        expect(screen.queryByTestId('webauthn-register-dialog')).not.toBeInTheDocument();
    });
});
