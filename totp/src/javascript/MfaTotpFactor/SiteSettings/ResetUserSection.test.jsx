import React from 'react';
import {describe, it, expect, vi} from 'vitest';
import {render, screen, waitFor} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import {MockedProvider} from '@apollo/client/testing';
import ResetUserSection from './ResetUserSection';
import {ResetUserMfaMutation} from './SiteSettings.gql';

// ResetUserSection only needs the presentational shell from moonstone - render small native
// substitutes instead of the real design-system bundle, same rationale as SiteSettings.test.jsx.
vi.mock('@jahia/moonstone', () => ({
    Button: ({label, onClick, isDisabled, ...props}) => (
        <button type="button" disabled={isDisabled} onClick={onClick} {...props}>{label}</button>
    ),
    Typography: ({children, ...props}) => <span {...props}>{children}</span>
}));

const SITE_KEY = 'mySite';

function resetSuccess(userId) {
    return {
        request: {query: ResetUserMfaMutation, variables: {userId, siteKey: SITE_KEY}},
        result: {data: {upa: {mfaFactors: {totp: {resetUserMfa: true}}}}}
    };
}

// A mock whose resolution never settles within the test, so the assertions can observe the
// button's "in flight" ("Resetting…") label before the mutation completes.
function resetPending(userId) {
    return {
        request: {query: ResetUserMfaMutation, variables: {userId, siteKey: SITE_KEY}},
        delay: 60 * 1000,
        result: {data: {upa: {mfaFactors: {totp: {resetUserMfa: true}}}}}
    };
}

function renderSection(mocks) {
    return render(
        <MockedProvider mocks={mocks}>
            <ResetUserSection siteKey={SITE_KEY}/>
        </MockedProvider>
    );
}

describe('ResetUserSection - arm-then-confirm gating', () => {
    it('does not fire the reset mutation on a single click of the primary button', async () => {
        const user = userEvent.setup();
        renderSection([resetSuccess('alice')]);

        await user.type(screen.getByTestId('reset-user-input'), 'alice');
        await user.click(screen.getByTestId('reset-user-btn'));

        // Only armed: the irreversibility warning appears, but the mutation has not fired -
        // no "done" status yet, and the confirm step is present for a second, explicit click.
        expect(screen.getByTestId('reset-user-confirm')).toBeInTheDocument();
        expect(screen.queryByTestId('reset-user-done')).not.toBeInTheDocument();
    });

    it('fires the mutation only after the second, explicit confirmation click', async () => {
        const user = userEvent.setup();
        renderSection([resetSuccess('alice')]);

        await user.type(screen.getByTestId('reset-user-input'), 'alice');
        await user.click(screen.getByTestId('reset-user-btn'));
        await user.click(screen.getByTestId('reset-user-confirm-btn'));

        expect(await screen.findByTestId('reset-user-done')).toBeInTheDocument();
    });

    it('re-disarms the confirmation when the username is edited after arming', async () => {
        const user = userEvent.setup();
        renderSection([resetSuccess('alice'), resetSuccess('aliceX')]);

        await user.type(screen.getByTestId('reset-user-input'), 'alice');
        await user.click(screen.getByTestId('reset-user-btn'));
        expect(screen.getByTestId('reset-user-confirm')).toBeInTheDocument();

        // Editing the username after arming is a change of intent: the confirm step must
        // disappear so a stale confirm click can't reset the wrong (or a half-typed) user.
        await user.type(screen.getByTestId('reset-user-input'), 'X');

        expect(screen.queryByTestId('reset-user-confirm')).not.toBeInTheDocument();
    });

    it('disables the primary button until a username is entered', async () => {
        renderSection([]);

        expect(screen.getByTestId('reset-user-btn')).toBeDisabled();
    });

    it('lets the admin cancel the armed confirmation without resetting anything', async () => {
        const user = userEvent.setup();
        renderSection([resetSuccess('alice')]);

        await user.type(screen.getByTestId('reset-user-input'), 'alice');
        await user.click(screen.getByTestId('reset-user-btn'));
        await user.click(screen.getByTestId('reset-user-cancel-btn'));

        expect(screen.queryByTestId('reset-user-confirm')).not.toBeInTheDocument();
        expect(screen.queryByTestId('reset-user-done')).not.toBeInTheDocument();
    });
});

describe('ResetUserSection - in-flight state', () => {
    it('shows a "Resetting…" label on the confirm button while the mutation is in flight', async () => {
        const user = userEvent.setup();
        renderSection([resetPending('alice')]);

        await user.type(screen.getByTestId('reset-user-input'), 'alice');
        await user.click(screen.getByTestId('reset-user-btn'));
        await user.click(screen.getByTestId('reset-user-confirm-btn'));

        await waitFor(() => {
            expect(screen.getByTestId('reset-user-confirm-btn')).toHaveTextContent('siteSettings.reset.resetting');
        });
        expect(screen.getByTestId('reset-user-confirm-btn')).toBeDisabled();
    });
});

describe('ResetUserSection - error path', () => {
    it('surfaces a mutation error to the admin instead of swallowing it', async () => {
        const user = userEvent.setup();
        const failingMock = {
            request: {query: ResetUserMfaMutation, variables: {userId: 'alice', siteKey: SITE_KEY}},
            error: new Error('permission_denied')
        };
        renderSection([failingMock]);

        await user.type(screen.getByTestId('reset-user-input'), 'alice');
        await user.click(screen.getByTestId('reset-user-btn'));
        await user.click(screen.getByTestId('reset-user-confirm-btn'));

        expect(await screen.findByTestId('reset-user-error')).toBeInTheDocument();
        expect(screen.queryByTestId('reset-user-done')).not.toBeInTheDocument();
    });
});
