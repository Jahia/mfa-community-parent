/**
 * Base structure for the GraphQL APIs on successful responses.
 */
export interface BaseSuccess {
  success: true;
  remainingFactors: Array<string>;
}

export interface MfaError {
  code: string;
  arguments?: Array<{ name: string; value: string }>;
}

/**
 * Base structure for the GraphQL APIs on error response.
 * The error contains a `code` and an optional array of `arguments` (with a `name` and `value`)
 */
export interface BaseError {
  success: false;
  error: MfaError;
  fatalError?: boolean;
}

/**
 * Extracts an MFA error code from a top-level GraphQL error (a server-side
 * DataFetchingException carries the error code as its message). Returns null when the
 * response has no top-level errors.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function topLevelError(result: any): MfaError | null {
  const message: string | undefined = result?.errors?.[0]?.message;
  if (!message) {
    return null;
  }
  const match = /factor\.[a-z0-9_.]+/.exec(message);
  return { code: match ? match[0] : "unexpected_error" };
}

/**
 * A network/transport failure (fetch rejected, or the response was not valid JSON). Returned by
 * every service so a dropped connection becomes a typed, non-fatal error the form can render and
 * recover from, instead of an unhandled promise rejection that hangs the UI silently.
 */
export function networkError(): BaseError {
  return {
    success: false,
    error: { code: "network_error" },
    fatalError: false,
  };
}

/**
 * Creates an error response based on provided session and factor errors.
 * If neither session nor factor errors are provided, an "unexpected_error" error is returned
 * with a fatal flag set to true.
 */
export function createError(sessionError?: MfaError, factorError?: MfaError): BaseError {
  if (sessionError) {
    return {
      success: false,
      error: sessionError,
      fatalError: true,
    };
  }
  if (factorError) {
    return {
      success: false,
      error: factorError,
      fatalError: false,
    };
  }
  return {
    success: false,
    error: { code: "unexpected_error" },
    fatalError: true,
  };
}
