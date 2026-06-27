/**
 * Converts error arguments from array format to object format for i18next interpolation.
 */
export function convertErrorArgsToInterpolation(error: {
  code: string;
  arguments?: Array<{ name: string; value: string }>;
}): { key: string; interpolation: Record<string, string> } {
  const interpolationData: Record<string, string> = {};
  if (error.arguments) {
    error.arguments.forEach((arg) => {
      interpolationData[arg.name] = arg.value;
    });
  }
  return {
    key: error.code,
    interpolation: interpolationData,
  };
}

/** A function with i18next's `t(key, options)` signature (the part this module needs). */
type TranslateFn = (
  key: string,
  options?: Record<string, unknown>,
) => string;

/**
 * Renders a server-supplied MFA error code to a localized message, degrading gracefully (item 14):
 * an unmapped code falls back to the generic {@code unexpected_error} message instead of leaking
 * the raw machine string (e.g. "factor.totp.some_new_code") into the UI.
 */
export function translateError(
  t: TranslateFn,
  error: { code: string; arguments?: Array<{ name: string; value: string }> },
): string {
  const { key, interpolation } = convertErrorArgsToInterpolation(error);
  return t(key, { defaultValue: t("unexpected_error"), ...interpolation });
}
