import { type BaseError, type BaseSuccess, createError } from "./common";

type VerifyEmailFactorResultSuccess = BaseSuccess;
type VerifyEmailFactorResultError = BaseError;
export type VerifyEmailFactorResult = VerifyEmailFactorResultSuccess | VerifyEmailFactorResultError;

export default async function verifyEmailCodeFactor(
  apiRoot: string,
  code: string,
): Promise<VerifyEmailFactorResult> {
  const response = await fetch(apiRoot, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      query: /* GraphQL */ `
        mutation verifyEmailCodeFactor($code: String!, $factorType: String!) {
          upa {
            mfaFactors {
              emailCode {
                verify(code: $code) {
                  session {
                    factorState(factorType: $factorType) {
                      verified
                      error {
                        code
                        arguments {
                          name
                          value
                        }
                      }
                    }
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
      variables: { code, factorType: "email_code" },
    }),
  });
  const result = await response.json();
  const verification = result?.data?.upa?.mfaFactors?.emailCode?.verify;
  const success = verification?.session?.factorState?.verified;
  if (success) {
    return { success: true, remainingFactors: verification.session.remainingFactors };
  } else {
    return createError(
      verification?.session?.error,
      verification?.session?.factorState?.error,
    );
  }
}
