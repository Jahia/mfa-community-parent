import React from 'react';
import {describe, it, expect, vi} from 'vitest';
import {render, screen} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import BackupCodesDialog from './BackupCodesDialog';

// BackupCodesDialog only needs the presentational shell from moonstone - render small native
// substitutes instead of the real design-system bundle, same rationale as the other admin
// screens' tests. The mock Modal exposes an explicit "dismiss" affordance (mirroring the real
// component's backdrop-click/Escape path, which calls onOpenChange(false)) so the data-loss
// guard in onOpenChange can be exercised without depending on moonstone's own key/backdrop
// handling internals.
vi.mock('@jahia/moonstone', () => ({
    Button: ({label, onClick, isDisabled, ...props}) => (
        <button type="button" disabled={isDisabled} onClick={onClick} {...props}>{label}</button>
    ),
    Typography: ({children, ...props}) => <span {...props}>{children}</span>,
    Modal: ({isOpen, onOpenChange, children}) => (isOpen ? (
        <div role="dialog">
            {children}
            <button type="button" data-testid="mock-modal-dismiss" onClick={() => onOpenChange(false)}>
                dismiss (backdrop/Escape)
            </button>
        </div>
    ) : null),
    ModalHeader: ({title}) => <h2>{title}</h2>,
    ModalBody: ({children}) => <div>{children}</div>,
    ModalFooter: ({children}) => <div>{children}</div>
}));

const codes = ['aaaa-1111', 'bbbb-2222', 'cccc-3333'];

describe('BackupCodesDialog - one-shot codes rendering', () => {
    it('renders every code exactly once', () => {
        render(<BackupCodesDialog isOpen codes={codes} onClose={vi.fn()}/>);

        const list = screen.getByTestId('backup-codes-list');
        for (const code of codes) {
            expect(list).toHaveTextContent(code);
        }
    });

    it('renders nothing when closed', () => {
        render(<BackupCodesDialog isOpen={false} codes={codes} onClose={vi.fn()}/>);

        expect(screen.queryByTestId('backup-codes-list')).not.toBeInTheDocument();
    });
});

describe('BackupCodesDialog - data-loss guard: acknowledgement required to close', () => {
    it('keeps the close button disabled until the acknowledgement checkbox is checked', async () => {
        const user = userEvent.setup();
        render(<BackupCodesDialog isOpen codes={codes} onClose={vi.fn()}/>);

        expect(screen.getByTestId('backup-codes-close-btn')).toBeDisabled();

        await user.click(screen.getByTestId('backup-codes-ack'));

        expect(screen.getByTestId('backup-codes-close-btn')).toBeEnabled();
    });

    it('does not call onClose when the close button is clicked before acknowledging', async () => {
        const user = userEvent.setup();
        const onClose = vi.fn();
        render(<BackupCodesDialog isOpen codes={codes} onClose={onClose}/>);

        // The button is disabled, but this asserts on the observable contract (no callback
        // fired), not just the disabled attribute - the guard is what actually matters.
        await user.click(screen.getByTestId('backup-codes-close-btn'));

        expect(onClose).not.toHaveBeenCalled();
    });

    it('calls onClose once acknowledged and the close button is clicked', async () => {
        const user = userEvent.setup();
        const onClose = vi.fn();
        render(<BackupCodesDialog isOpen codes={codes} onClose={onClose}/>);

        await user.click(screen.getByTestId('backup-codes-ack'));
        await user.click(screen.getByTestId('backup-codes-close-btn'));

        expect(onClose).toHaveBeenCalledTimes(1);
    });

    it('ignores a backdrop/Escape dismiss attempt before the user has acknowledged the codes', async () => {
        const user = userEvent.setup();
        const onClose = vi.fn();
        render(<BackupCodesDialog isOpen codes={codes} onClose={onClose}/>);

        await user.click(screen.getByTestId('mock-modal-dismiss'));

        expect(onClose).not.toHaveBeenCalled();
        // The dialog (and the codes) must still be on screen - dismissing must not have worked.
        expect(screen.getByTestId('backup-codes-list')).toBeInTheDocument();
    });

    it('honours a backdrop/Escape dismiss attempt once the user has acknowledged the codes', async () => {
        const user = userEvent.setup();
        const onClose = vi.fn();
        render(<BackupCodesDialog isOpen codes={codes} onClose={onClose}/>);

        await user.click(screen.getByTestId('backup-codes-ack'));
        await user.click(screen.getByTestId('mock-modal-dismiss'));

        expect(onClose).toHaveBeenCalledTimes(1);
    });
});
