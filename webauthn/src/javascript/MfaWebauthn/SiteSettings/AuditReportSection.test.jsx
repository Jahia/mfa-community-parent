import React from 'react';
import {describe, it, expect, vi} from 'vitest';
import {render, screen} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import {MockedProvider} from '@apollo/client/testing';
import AuditReportSection, {isLazyQueryResultEmpty} from './AuditReportSection';
import {AuditEventsQuery, EnrollmentReportQuery} from './SiteSettings.gql';

// AuditReportSection only needs the presentational shell from moonstone - render small native
// substitutes instead of the real design-system bundle, same rationale as the other admin
// screens' tests.
vi.mock('@jahia/moonstone', () => ({
    Button: ({label, onClick, isDisabled, ...props}) => (
        <button type="button" disabled={isDisabled} onClick={onClick} {...props}>{label}</button>
    ),
    Typography: ({children, ...props}) => <span {...props}>{children}</span>,
    Loader: () => <div data-testid="loader">loading</div>,
    Key: () => <span data-testid="key-icon"/>
}));

const SITE_KEY = 'mySite';

function renderSection(mocks) {
    return render(
        <MockedProvider mocks={mocks}>
            <AuditReportSection siteKey={SITE_KEY}/>
        </MockedProvider>
    );
}

describe('isLazyQueryResultEmpty', () => {
    it('is false while the query has never been called', () => {
        expect(isLazyQueryResultEmpty({called: false, loading: false, error: undefined}, false)).toBe(false);
    });

    it('is false while the query is still loading', () => {
        expect(isLazyQueryResultEmpty({called: true, loading: true, error: undefined}, false)).toBe(false);
    });

    it('is false when the query errored (that is a distinct "error" state, not "empty")', () => {
        expect(isLazyQueryResultEmpty({called: true, loading: false, error: new Error('boom')}, false)).toBe(false);
    });

    it('is true once the query has settled successfully with no data', () => {
        expect(isLazyQueryResultEmpty({called: true, loading: false, error: undefined}, false)).toBe(true);
    });

    it('is false once the query has settled successfully with data', () => {
        expect(isLazyQueryResultEmpty({called: true, loading: false, error: undefined}, true)).toBe(false);
    });
});

describe('AuditReportSection - initial state', () => {
    it('does not run either query until the admin asks for it', () => {
        renderSection([]);

        expect(screen.queryByTestId('audit-empty')).not.toBeInTheDocument();
        expect(screen.queryByTestId('audit-table')).not.toBeInTheDocument();
        expect(screen.queryByTestId('enrollment-report')).not.toBeInTheDocument();
    });
});

describe('AuditReportSection - empty results', () => {
    it('shows the "no events" message when the audit query returns no rows', async () => {
        const user = userEvent.setup();
        const mock = {
            request: {query: AuditEventsQuery, variables: {siteKey: SITE_KEY, limit: 50}},
            result: {data: {mfaWebauthn: {auditEvents: []}}}
        };
        renderSection([mock]);

        await user.click(screen.getByTestId('load-audit-btn'));

        expect(await screen.findByTestId('audit-empty')).toBeInTheDocument();
        expect(screen.queryByTestId('audit-table')).not.toBeInTheDocument();
    });
});

describe('AuditReportSection - populated results', () => {
    it('renders a row per audit event once the admin loads them', async () => {
        const user = userEvent.setup();
        const mock = {
            request: {query: AuditEventsQuery, variables: {siteKey: SITE_KEY, limit: 50}},
            result: {
                data: {
                    mfaWebauthn: {
                        auditEvents: [
                            {eventType: 'REGISTER', outcome: 'SUCCESS', userId: 'alice', timestamp: '1700000000000', detail: 'first registration'},
                            {eventType: 'LOGIN', outcome: 'FAILURE', userId: 'bob', timestamp: '1700000100000', detail: 'assertion rejected'}
                        ]
                    }
                }
            }
        };
        renderSection([mock]);

        await user.click(screen.getByTestId('load-audit-btn'));

        const table = await screen.findByTestId('audit-table');
        expect(table).toHaveTextContent('alice');
        expect(table).toHaveTextContent('bob');
        expect(screen.queryByTestId('audit-empty')).not.toBeInTheDocument();
    });

    it('renders the enrollment summary once the admin loads the report', async () => {
        const user = userEvent.setup();
        const mock = {
            request: {query: EnrollmentReportQuery, variables: {siteKey: SITE_KEY, limit: 200}},
            result: {
                data: {
                    mfaWebauthn: {
                        enrollmentReport: {
                            totalUsers: 10,
                            registeredUsers: 6,
                            notRegistered: ['carol', 'dave'],
                            truncated: false
                        }
                    }
                }
            }
        };
        renderSection([mock]);

        await user.click(screen.getByTestId('load-report-btn'));

        const report = await screen.findByTestId('enrollment-report');
        expect(report).toHaveTextContent('carol');
        expect(report).toHaveTextContent('dave');
    });
});

describe('AuditReportSection - error paths', () => {
    it('surfaces an audit query failure to the admin instead of showing "no events"', async () => {
        const user = userEvent.setup();
        const mock = {
            request: {query: AuditEventsQuery, variables: {siteKey: SITE_KEY, limit: 50}},
            error: new Error('network down')
        };
        renderSection([mock]);

        await user.click(screen.getByTestId('load-audit-btn'));

        expect(await screen.findByTestId('audit-error')).toBeInTheDocument();
        expect(screen.queryByTestId('audit-empty')).not.toBeInTheDocument();
    });

    it('surfaces an enrollment report query failure to the admin instead of showing the summary', async () => {
        const user = userEvent.setup();
        const mock = {
            request: {query: EnrollmentReportQuery, variables: {siteKey: SITE_KEY, limit: 200}},
            error: new Error('network down')
        };
        renderSection([mock]);

        await user.click(screen.getByTestId('load-report-btn'));

        expect(await screen.findByTestId('report-error')).toBeInTheDocument();
        expect(screen.queryByTestId('enrollment-report')).not.toBeInTheDocument();
    });
});
