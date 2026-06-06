import { type BaseError, topLevelError } from "./common";

export interface ConfirmEnrollTotpResultSuccess {
  success: true;
  backupCodes: string[];
  remainingFactors: string[];
}
export type ConfirmEnrollTotpResult = ConfirmEnrollTotpResultSuccess | BaseError;

/**
 * Confirms an inline TOTP enrollment with the first authenticator code. On the pre-auth path
 * the server persists the enrollment and immediately verifies the same code through the
 * standard chokepoint — when {@code remainingFactors} comes back empty the login is complete.
 * Returns the one-shot backup codes to display.
 */
export default async function confirmEnrollTotp(
  apiRoot: string,
  code: string,
): Promise<ConfirmEnrollTotpResult> {
  const response = await fetch(apiRoot, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      query: /* GraphQL */ `
        mutation confirmEnrollTotp($code: String!) {
          upa {
            mfaFactors {
              totp {
                confirmEnroll(code: $code) {
                  backupCodes
                  session {
                    initiated
                    remainingFactors
                    error {
                      code
                      arguments {
                        name
                        value
                      }
                    }
                  }
                }
              }
            }
          }
        }
      `,
      variables: { code },
    }),
  });
  const result = await response.json();
  const confirm = result?.data?.upa?.mfaFactors?.totp?.confirmEnroll;
  if (confirm?.backupCodes) {
    return {
      success: true,
      backupCodes: confirm.backupCodes,
      remainingFactors: confirm.session?.remainingFactors ?? [],
    };
  }
  return {
    success: false,
    error: topLevelError(result) ?? confirm?.session?.error ?? { code: "unexpected_error" },
    fatalError: false,
  };
}
