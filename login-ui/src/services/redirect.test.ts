import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getSafeRedirect } from "./redirect";

/**
 * Open-redirect guard for the post-login `redirect=` param, the client-side mirror of the
 * server's MfaUrlsTest. A redirect value must never be able to send the user to an external host
 * (https://attacker.example, //attacker.example, the /\attacker.example browser backslash quirk)
 * or trigger a dangerous scheme (javascript:, data:, …). Anything unsafe falls back to
 * contextPath + "/".
 *
 * jsdom serves these tests from http://localhost:3000, so that is the "same origin".
 */
describe("getSafeRedirect", () => {
  const CTX = "/cms";
  const FALLBACK = CTX + "/";
  const ORIGIN = "http://localhost:3000";

  beforeEach(() => {
    // Silence the expected "Invalid redirect URL" warning on malformed inputs.
    vi.spyOn(console, "warn").mockImplementation(() => {});
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  // --- blank / missing -> contextPath fallback ---

  it("falls back to contextPath for a null redirect", () => {
    expect(getSafeRedirect(null, CTX)).toBe(FALLBACK);
  });

  it("falls back to contextPath for an empty redirect", () => {
    expect(getSafeRedirect("", CTX)).toBe(FALLBACK);
  });

  // --- safe server-relative paths pass through verbatim ---

  it("accepts a plain server-relative path", () => {
    expect(getSafeRedirect("/sites/mySite/home.html", CTX)).toBe("/sites/mySite/home.html");
  });

  it("accepts a server-relative path with query and hash", () => {
    expect(getSafeRedirect("/login?site=a&lang=en#top", CTX)).toBe("/login?site=a&lang=en#top");
  });

  it("accepts the root path", () => {
    expect(getSafeRedirect("/", CTX)).toBe("/");
  });

  // --- absolute URLs ---

  it("rejects an absolute https URL to another host", () => {
    expect(getSafeRedirect("https://attacker.example/phish", CTX)).toBe(FALLBACK);
  });

  it("rejects an absolute http URL to another host", () => {
    expect(getSafeRedirect("http://attacker.example", CTX)).toBe(FALLBACK);
  });

  it("collapses a same-origin absolute URL down to its path", () => {
    expect(getSafeRedirect(`${ORIGIN}/dashboard?x=1#h`, CTX)).toBe("/dashboard?x=1#h");
  });

  // --- protocol-relative variants ---

  it("rejects a protocol-relative //host URL", () => {
    expect(getSafeRedirect("//attacker.example", CTX)).toBe(FALLBACK);
  });

  it("rejects the /\\host backslash quirk (slash + backslash)", () => {
    expect(getSafeRedirect("/\\attacker.example", CTX)).toBe(FALLBACK);
  });

  it("rejects a backslash-prefixed //attacker variant", () => {
    expect(getSafeRedirect("/\\/attacker.example", CTX)).toBe(FALLBACK);
  });

  // --- dangerous schemes ---

  it("rejects a javascript: URL", () => {
    expect(getSafeRedirect("javascript:alert(1)", CTX)).toBe(FALLBACK);
  });

  it("rejects a data: URL", () => {
    expect(getSafeRedirect("data:text/html,<script>alert(1)</script>", CTX)).toBe(FALLBACK);
  });

  it("rejects a vbscript: URL", () => {
    expect(getSafeRedirect("vbscript:msgbox(1)", CTX)).toBe(FALLBACK);
  });

  it("rejects a file: URL", () => {
    expect(getSafeRedirect("file:///etc/passwd", CTX)).toBe(FALLBACK);
  });

  it("rejects a blob: URL", () => {
    expect(getSafeRedirect("blob:http://localhost:3000/uuid", CTX)).toBe(FALLBACK);
  });

  // --- mixed-case scheme variants ---

  it("rejects a mixed-case JavaScript: URL", () => {
    expect(getSafeRedirect("JaVaScRiPt:alert(1)", CTX)).toBe(FALLBACK);
  });

  it("rejects a mixed-case Data: URL", () => {
    expect(getSafeRedirect("DATA:text/html,x", CTX)).toBe(FALLBACK);
  });

  // --- percent-encoded variants ---

  it("rejects a percent-encoded javascript scheme", () => {
    // %6a%61%76%61%73%63%72%69%70%74 decodes to "javascript"
    expect(
      getSafeRedirect("%6a%61%76%61%73%63%72%69%70%74:alert(1)", CTX),
    ).toBe(FALLBACK);
  });

  it("rejects a percent-encoded data scheme", () => {
    expect(getSafeRedirect("%64%61%74%61:text/html,x", CTX)).toBe(FALLBACK);
  });

  // --- control characters / whitespace / backslashes ---

  it("rejects a path containing a backslash", () => {
    expect(getSafeRedirect("/path\\segment", CTX)).toBe(FALLBACK);
  });

  it("rejects a path with an embedded newline (header-injection style)", () => {
    expect(getSafeRedirect("/login\r\nSet-Cookie: x", CTX)).toBe(FALLBACK);
  });

  it("rejects a path with a NUL control character", () => {
    expect(getSafeRedirect("/path\u0000x", CTX)).toBe(FALLBACK);
  });

  it("rejects a path with a tab control character", () => {
    expect(getSafeRedirect("/login\tpage", CTX)).toBe(FALLBACK);
  });

  it("rejects a path containing a space", () => {
    expect(getSafeRedirect("/login page.html", CTX)).toBe(FALLBACK);
  });

  // --- relative without leading slash ---

  it("treats a leading-slash-less relative path as same-origin and returns its resolved path", () => {
    // "sites/x" resolves against the jsdom origin to /sites/x — still same-origin, so safe.
    expect(getSafeRedirect("sites/mySite/home.html", CTX)).toBe("/sites/mySite/home.html");
  });
});
