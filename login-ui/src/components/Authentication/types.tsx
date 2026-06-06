import type { JCRNodeWrapper } from "org.jahia.services.content";

export interface Props {
  /**
   * The context path of Jahia. `''` by default; `'/<ctx>'` when `CATALINA_CONTEXT` is set.
   */
  contextPath: string;
  /**
   * The site key of the page hosting the component (resolved server-side — the page URL may be
   * a vanity/server-name URL that carries no /sites/<key> prefix).
   */
  siteKey?: string;
  logo?: JCRNodeWrapper;
  loginEmailFieldLabel: string;
  loginPasswordFieldLabel: string;
  loginSubmitButtonLabel: string;
  loginBelowPasswordFieldHtml?: string;
  loginAdditionalActionHtml?: string;
  totpCodeVerificationFieldLabel: string;
  totpCodeVerificationSubmitButtonLabel: string;
  totpCodeVerificationHelpHtml?: string;
  totpCodeVerificationBackupCodeHintHtml?: string;
}
