import DOMPurify from "dompurify";

/**
 * Sanitizes CMS-editor-authored HTML before it is injected via dangerouslySetInnerHTML.
 *
 * The login surface renders as an island: the server pre-renders on GraalVM, then the browser
 * hydrates. DOMPurify needs a real DOM, which GraalVM's SSR runtime does not provide, so we only
 * sanitize on the client (typeof window guard) and render nothing during SSR — the island
 * re-renders the sanitized markup on hydration. This keeps SSR from crashing while still
 * guaranteeing the final, visible DOM is sanitized.
 *
 * The config is permissive-but-safe: intended formatting (links, emphasis, lists, line breaks)
 * survives, while scripts, event handlers and dangerous URL schemes are stripped.
 */
export function sanitizeHtml(dirty: string | undefined): string {
  if (!dirty) {
    return "";
  }
  if (typeof window === "undefined") {
    // Server-side (GraalVM): no DOM to sanitize against. The island re-sanitizes on hydration.
    return "";
  }
  return DOMPurify.sanitize(dirty, {
    USE_PROFILES: { html: true },
    ADD_ATTR: ["target", "rel"],
  });
}
