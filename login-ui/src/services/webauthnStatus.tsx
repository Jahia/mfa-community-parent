import { type BaseError, networkError, topLevelError } from "./common";

export interface WebauthnCredential {
  credentialId: string;
  nickname: string | null;
  signCount: number;
  createdAt: string | null;
  lastUsedAt: string | null;
  transports: string[];
  aaguid: string | null;
}
export interface WebauthnStatusResultSuccess {
  success: true;
  supported: boolean;
  registered: boolean;
  credentials: WebauthnCredential[];
}
/**
 * The WebAuthn factor is not installed on this node at all: the {@code mfaWebauthn} GraphQL type
 * does not exist in the schema, so the query fails validation before execution. Distinct from a
 * runtime {@link BaseError} — the settings panel omits the WebAuthn section entirely on this signal
 * (true soft-wire) rather than surfacing a spurious error for a factor the node simply does not offer.
 */
export interface WebauthnUnavailableResult {
  success: false;
  unavailable: true;
}
export type WebauthnStatusResult =
  | WebauthnStatusResultSuccess
  | WebauthnUnavailableResult
  | BaseError;

/**
 * Reads the current authenticated user's WebAuthn state (self-service): whether the platform
 * supports it on this site and the list of registered passkeys. Drives the settings panel's
 * WebAuthn section.
 */
export default async function webauthnStatus(apiRoot: string): Promise<WebauthnStatusResult> {
  try {
    const response = await fetch(apiRoot, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        query: /* GraphQL */ `
          query webauthnStatus {
            mfaWebauthn {
              supported
              status {
                registered
                credentials {
                  credentialId
                  nickname
                  signCount
                  createdAt
                  lastUsedAt
                  transports
                  aaguid
                }
              }
            }
          }
        `,
      }),
    });
    const result = await response.json();
    const root = result?.data?.mfaWebauthn;
    const status = root?.status;
    if (status) {
      return {
        success: true,
        supported: Boolean(root.supported),
        registered: Boolean(status.registered),
        credentials: Array.isArray(status.credentials) ? status.credentials : [],
      };
    }
    // The mfaWebauthn type is absent from the schema (webauthn bundle not installed on this node):
    // GraphQL rejects the query at VALIDATION, before execution. Jahia's graphql-dxm-provider
    // reports that as a top-level error whose `extensions.classification` is "ValidationError"
    // (with data: null). For this fixed, hardcoded query the ONLY way validation can fail is the
    // mfaWebauthn field/type not existing — so that classification is our reliable,
    // message-independent "WebAuthn not available here" signal → soft-wire: the caller omits the
    // section rather than showing an error. A runtime/execution error carries a different
    // classification and falls through to the normal error path below, unchanged.
    const errors: Array<{ extensions?: { classification?: string } }> = Array.isArray(result?.errors)
      ? result.errors
      : [];
    if (errors.some((e) => e?.extensions?.classification === "ValidationError")) {
      return { success: false, unavailable: true };
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
