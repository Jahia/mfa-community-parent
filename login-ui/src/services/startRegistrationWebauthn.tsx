import { type BaseError, topLevelError } from "./common";

export interface StartRegistrationWebauthnResultSuccess {
  success: true;
  /** The navigator.credentials.create() options JSON the browser must consume. */
  creationOptionsJson: string;
}
export type StartRegistrationWebauthnResult = StartRegistrationWebauthnResultSuccess | BaseError;

/**
 * Begins a WebAuthn registration ceremony during sign-in (inline, pre-authentication).
 * Allowed by the server only for an initiated MFA session whose user has no enforced factor
 * configured — see the pre-auth guard on {@code webauthn.startRegistration}.
 */
export default async function startRegistrationWebauthn(
  apiRoot: string,
): Promise<StartRegistrationWebauthnResult> {
  const response = await fetch(apiRoot, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      query: /* GraphQL */ `
        mutation startRegistrationWebauthn {
          upa {
            mfaFactors {
              webauthn {
                startRegistration {
                  publicKeyCredentialCreationOptions
                }
              }
            }
          }
        }
      `,
    }),
  });
  const result = await response.json();
  const options =
    result?.data?.upa?.mfaFactors?.webauthn?.startRegistration?.publicKeyCredentialCreationOptions;
  if (options) {
    return { success: true, creationOptionsJson: options };
  }
  return {
    success: false,
    error: topLevelError(result) ?? { code: "unexpected_error" },
    fatalError: false,
  };
}
