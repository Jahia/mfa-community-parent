import { type BaseError, networkError, topLevelError } from "./common";

export interface EnrollTotpResultSuccess {
  success: true;
  secret: string;
  otpauthUri: string;
  issuer: string;
  accountName: string;
}
export type EnrollTotpResult = EnrollTotpResultSuccess | BaseError;

/**
 * Starts a TOTP enrollment during sign-in (inline, pre-authentication). Allowed by the server
 * only for an initiated MFA session whose user has no enforced factor configured — see the
 * pre-auth guard on {@code totp.enroll}. Returns the fresh secret + otpauth:// URI to render
 * as a QR code.
 */
export default async function enrollTotp(apiRoot: string): Promise<EnrollTotpResult> {
  try {
    const response = await fetch(apiRoot, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        query: /* GraphQL */ `
          mutation enrollTotp {
            upa {
              mfaFactors {
                totp {
                  enroll {
                    secret
                    otpauthUri
                    issuer
                    accountName
                  }
                }
              }
            }
          }
        `,
      }),
    });
    const result = await response.json();
    const enroll = result?.data?.upa?.mfaFactors?.totp?.enroll;
    if (enroll?.secret && enroll?.otpauthUri) {
      return {
        success: true,
        secret: enroll.secret,
        otpauthUri: enroll.otpauthUri,
        issuer: enroll.issuer,
        accountName: enroll.accountName,
      };
    }
    return {
      success: false,
      error: topLevelError(result) ?? { code: "unexpected_error" },
      fatalError: false,
    };
  } catch {
    return networkError();
  }
}
