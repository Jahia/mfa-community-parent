import React from 'react';
import {describe, it, expect, vi} from 'vitest';
import {render, screen} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import CodePromptDialog from './CodePromptDialog';

// CodePromptDialog only needs the presentational shell from moonstone - render small native
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

const baseProps = {
    isOpen: true,
    title: 'Disable two-factor authentication',
    description: 'Enter your current 6-digit code to confirm disabling.',
    acceptLabel: 'Disable',
    onCancel: vi.fn(),
    onAccept: vi.fn()
};

describe('CodePromptDialog - no backup-code offer (server path is TOTP-only)', () => {
    it('does not mention or accept backup codes when isBackupCodeAllowed is not set', async () => {
        // This mirrors the two real call sites in MyMfaSettings.jsx (disable/regenerate), neither
        // of which passes isBackupCodeAllowed: the server-side mutations only ever verify a TOTP
        // code, so offering a backup code here would walk a locked-out user into burning
        // rate-limiter attempts on a guaranteed-invalid submission.
        const user = userEvent.setup();
        render(<CodePromptDialog {...baseProps}/>);

        // No i18n instance is initialised in this test environment, so react-i18next's `t()`
        // renders the raw key: asserting on that literal key (rather than translated English
        // copy) is what actually proves the backup-code hint was not rendered at all, and that
        // the field is labelled with the plain description rather than the "code or backup
        // code" label.
        expect(screen.queryByText('codePrompt.backupHint')).not.toBeInTheDocument();

        const input = screen.getByTestId('code-prompt-input');
        expect(input).toHaveAccessibleName(baseProps.description);
        await user.type(input, 'abcdefgh12');

        // Non-numeric characters are stripped: the field only ever accepts a 6-digit TOTP code.
        expect(input).toHaveValue('12');
    });

    it('caps the field at 6 digits when backup codes are not allowed', async () => {
        const user = userEvent.setup();
        render(<CodePromptDialog {...baseProps}/>);

        await user.type(screen.getByTestId('code-prompt-input'), '1234567890');

        expect(screen.getByTestId('code-prompt-input')).toHaveValue('123456');
    });
});

describe('CodePromptDialog - submission', () => {
    it('keeps Accept disabled until a full 6-digit code has been entered', async () => {
        const user = userEvent.setup();
        render(<CodePromptDialog {...baseProps}/>);

        expect(screen.getByTestId('code-prompt-accept-btn')).toBeDisabled();

        await user.type(screen.getByTestId('code-prompt-input'), '12345');
        expect(screen.getByTestId('code-prompt-accept-btn')).toBeDisabled();

        await user.type(screen.getByTestId('code-prompt-input'), '6');
        expect(screen.getByTestId('code-prompt-accept-btn')).toBeEnabled();
    });

    it('submits exactly the code the admin/user entered', async () => {
        const user = userEvent.setup();
        const onAccept = vi.fn();
        render(<CodePromptDialog {...baseProps} onAccept={onAccept}/>);

        await user.type(screen.getByTestId('code-prompt-input'), '654321');
        await user.click(screen.getByTestId('code-prompt-accept-btn'));

        expect(onAccept).toHaveBeenCalledTimes(1);
        expect(onAccept).toHaveBeenCalledWith('654321');
    });

    it('disables Accept while a submission is in flight, even with a valid code', async () => {
        const user = userEvent.setup();
        render(<CodePromptDialog {...baseProps} isLoading/>);

        await user.type(screen.getByTestId('code-prompt-input'), '654321');

        expect(screen.getByTestId('code-prompt-accept-btn')).toBeDisabled();
    });

    it('surfaces a server-provided error message to the user', () => {
        render(<CodePromptDialog {...baseProps} errorKey="errors.invalidCode"/>);

        expect(screen.getByTestId('code-prompt-error')).toHaveTextContent('errors.invalidCode');
    });

    it('lets the user cancel without submitting anything', async () => {
        const user = userEvent.setup();
        const onAccept = vi.fn();
        const onCancel = vi.fn();
        render(<CodePromptDialog {...baseProps} onAccept={onAccept} onCancel={onCancel}/>);

        await user.type(screen.getByTestId('code-prompt-input'), '654321');
        await user.click(screen.getByText('cancel'));

        expect(onCancel).toHaveBeenCalledTimes(1);
        expect(onAccept).not.toHaveBeenCalled();
    });

    it('renders nothing when closed', () => {
        render(<CodePromptDialog {...baseProps} isOpen={false}/>);

        expect(screen.queryByTestId('code-prompt-input')).not.toBeInTheDocument();
    });
});
