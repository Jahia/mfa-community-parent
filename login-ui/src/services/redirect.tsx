/**
 * Whether the value is a safe server-relative redirect target. Mirrors the server-side guard in
 * {@code MfaUrls.isSafeSiteRelativeUrl}: it must start with a single {@code /}, must NOT be
 * protocol-relative ({@code //host} or the {@code /\host} browser quirk), and must not contain
 * whitespace, control characters or backslashes. Keeping both sides identical closes the
 * open-redirect defense on the read path (server) and the write path (this UI).
 */
function isSafeSiteRelativeUrl(value: string): boolean {
  if (value.length === 0 || value[0] !== "/") {
    return false;
  }
  if (value.length > 1 && (value[1] === "/" || value[1] === "\\")) {
    return false; // protocol-relative: //host or /\host
  }
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c <= 0x20 || c === 0x5c /* backslash */ || c === 0x7f) {
      return false;
    }
  }
  return true;
}

function getSafeRedirect(redirect: string | null, contextPath: string): string {
  const DANGEROUS_SCHEMES = ["javascript:", "data:", "vbscript:", "file:", "blob:"];

  if (!redirect) {
    return contextPath + "/";
  }

  try {
    const decoded = decodeURIComponent(redirect).toLowerCase();

    if (DANGEROUS_SCHEMES.some((scheme) => decoded.startsWith(scheme))) {
      return contextPath + "/";
    }

    // Any value that already looks server-relative ("/...") must clear the same strict guard as
    // the server-side MfaUrls check. We do NOT fall through to URL() normalization for these,
    // because the WHATWG parser would silently "repair" hostile inputs (/\host -> //host,
    // "/login page" -> "/login%20page", a CRLF -> stripped) and hand back a value the server-side
    // guard would have rejected. Reject unsafe server-relative values outright to keep both sides
    // symmetric.
    if (redirect.charAt(0) === "/") {
      return isSafeSiteRelativeUrl(redirect) ? redirect : contextPath + "/";
    }

    // Otherwise it may be an absolute URL: accept it only if it resolves to the current origin,
    // and only return the reconstructed server-relative path when that path is itself safe.
    const url = new URL(redirect, window.location.origin);
    if (url.origin === window.location.origin && isSafeSiteRelativeUrl(url.pathname)) {
      return url.pathname + url.search + url.hash;
    }
  } catch (e) {
    console.warn("Invalid redirect URL", e);
  }

  return contextPath + "/";
}

export { getSafeRedirect };

/**
 * Redirects the user after a successful authentication, honouring a `redirect=`
 * query-string param only if it is a safe same-origin URL.
 */
export default function redirect(contextPath: string): void {
  const urlParams = new URLSearchParams(window.location.search);
  const redirectParam = urlParams.get("redirect");
  window.location.href = getSafeRedirect(redirectParam, contextPath);
}
