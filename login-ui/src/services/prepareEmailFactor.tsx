import { type BaseError, type BaseSuccess, createError } from "./common";

interface PrepareEmailFactorResultSuccess extends BaseSuccess {
  maskedEmail: string;
}
type PrepareEmailFactorResultError = BaseError;
export type PrepareEmailFactorResult =
  | PrepareEmailFactorResultSuccess
  | PrepareEmailFactorResultError;

export default async function prepareEmailFactor(
  apiRoot: string,
): Promise<PrepareEmailFactorResult> {
  const response = await fetch(apiRoot, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      query: /* GraphQL */ `
        mutation prepareEmailCodeFactor($factorType: String!) {
          upa {
            mfaFactors {
              emailCode {
                prepare {
                  session {
                    initiated
                    remainingFactors
                    factorState(factorType: $factorType) {
                      prepared
                      error {
                        code
                        arguments {
                          name
                          value
                        }
                      }
                    }
                    error {
                      code
                      arguments {
                        name
                        value
                      }
                    }
                  }
                  maskedEmail
                }
              }
            }
          }
        }
      `,
      variables: { factorType: "email_code" },
    }),
  });
  const result = await response.json();
  const preparation = result?.data?.upa?.mfaFactors?.emailCode?.prepare;
  const success =
    preparation?.session?.factorState?.prepared &&
    !preparation?.session?.factorState?.error &&
    preparation?.maskedEmail;
  if (success) {
    return {
      success: true,
      remainingFactors: preparation.session.remainingFactors,
      maskedEmail: preparation.maskedEmail,
    };
  } else {
    return createError(
      preparation?.session?.error,
      preparation?.session?.factorState?.error,
    );
  }
}
