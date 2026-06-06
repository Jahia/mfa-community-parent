/**
 * Helpers for the WebAuthn login UI spec — per-site activation, Relying Party
 * reconfiguration, and a Chrome-DevTools-Protocol virtual authenticator standing in for a
 * hardware security key (Electron / Chrome-family browsers only).
 */
import gql from 'graphql-tag';

/**
 * Enable (or disable) the WebAuthn factor on a site via the per-site GraphQL mutation.
 * Mirrors setSiteTotpSettings — enforcement itself is GLOBAL (setGlobalEnforcement).
 */
export function setSiteWebauthnSettings(siteKey: string, enabled: boolean) {
    return cy.apollo({
        mutation: gql`
            mutation SetSiteWebauthn($siteKey: String!, $enabled: Boolean!) {
                upa {
                    mfaFactors {
                        webauthn {
                            setSiteSettings(siteKey: $siteKey, enabled: $enabled) {
                                siteKey
                                enabled
                            }
                        }
                    }
                }
            }
        `,
        variables: {siteKey, enabled},
        errorPolicy: 'all',
    });
}

/**
 * Point the WebAuthn Relying Party at a different host through the provisioning API
 * (PID org.jahia.modules.webauthn). Inside the compose network the browser is on
 * http://jahia:8080, so specs must set rpId=jahia and restore rpId=localhost in after()
 * — credentials are scoped to the RP ID, a leftover value breaks other environments.
 */
export function setWebauthnRpId(rpId: string) {
    const password = Cypress.env('SUPER_USER_PASSWORD') as string;
    cy.request({
        method: 'POST',
        url: '/modules/api/provisioning',
        auth: {user: 'root', pass: password},
        headers: {'Content-Type': 'application/json'},
        body: [{
            editConfiguration: 'org.jahia.modules.webauthn',
            properties: {rpId},
        }],
    });
    // Give ConfigAdmin a moment to dispatch the @Modified event to WebAuthnConfig.
    cy.wait(2000);
}

/**
 * Attach a CTAP2 virtual authenticator through the Chrome DevTools Protocol.
 * automaticPresenceSimulation answers every navigator.credentials.create()/get() prompt
 * without a human touch; isUserVerified satisfies `userVerification: preferred`. The
 * authenticator lives at the BROWSER level for the whole session (it survives cy.visit
 * navigations AND test isolation), so this is idempotent — a second authenticator would
 * race the first one's credentials and fail assertions with NotAllowedError.
 */
let virtualAuthenticatorAdded = false;

export function addVirtualAuthenticator(): void {
    cy.wrap(null, {log: false}).then(() => {
        if (virtualAuthenticatorAdded) {
            return undefined;
        }
        return Cypress.automation('remote:debugger:protocol', {
            command: 'WebAuthn.enable',
            params: {},
        }).then(() =>
            Cypress.automation('remote:debugger:protocol', {
                command: 'WebAuthn.addVirtualAuthenticator',
                params: {
                    options: {
                        protocol: 'ctap2',
                        transport: 'internal',
                        hasResidentKey: true,
                        hasUserVerification: true,
                        isUserVerified: true,
                        automaticPresenceSimulation: true,
                    },
                },
            }),
        ).then(() => {
            virtualAuthenticatorAdded = true;
        });
    });
}
