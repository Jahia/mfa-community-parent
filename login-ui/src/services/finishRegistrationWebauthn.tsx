import { type BaseError, topLevelError } from "./common";

export interface FinishRegistrationWebauthnResultSuccess {
  success: true;
}
export type FinishRegistrationWebauthnResult = FinishRegistrationWebauthnResultSuccess | BaseError;

/**
 * Completes a WebAuthn registration ceremony with the navigator.credentials.create() response.
 * On the inline (pre-auth) path the session is NOT completed by this call — registration
 * produces an attestation, not an assertion — so the caller must immediately run the standard
 * prepare → navigator.credentials.get() → verify ceremony to finish signing in.
 */
export default async function finishRegistrationWebauthn(
  apiRoot: string,
  responseJson: string,
): Promise<FinishRegistrationWebauthnResult> {
  const response = await fetch(apiRoot, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      query: /* GraphQL */ `
        mutation finishRegistrationWebauthn($response: String!) {
          upa {
            mfaFactors {
              webauthn {
                finishRegistration(response: $response) {
                  registered
                }
              }
            }
          }
        }
      `,
      variables: { response: responseJson },
    }),
  });
  const result = await response.json();
  const registered = result?.data?.upa?.mfaFactors?.webauthn?.finishRegistration?.registered;
  if (registered) {
    return { success: true };
  }
  return {
    success: false,
    error: topLevelError(result) ?? { code: "unexpected_error" },
    fatalError: false,
  };
}
