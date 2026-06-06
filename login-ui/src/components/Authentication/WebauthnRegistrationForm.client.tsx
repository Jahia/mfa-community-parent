import { useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import { useApiRoot } from "../../hooks/ApiRootContext";
import {
  finishRegistrationWebauthn,
  prepareWebauthnFactor,
  startRegistrationWebauthn,
  verifyWebauthnFactor,
} from "../../services";
import { createCredential, getAssertion, isWebauthnSupported } from "../../services/webauthnBrowser";
import classes from "./component.module.css";
import ErrorMessage from "./ErrorMessage.client";
import { convertErrorArgsToInterpolation } from "../../services/i18n";
import type { MfaError } from "../../services/common";

interface WebauthnRegistrationFormProps {
  onComplete: (remainingFactors: string[]) => void;
  onFatalError: (error: MfaError) => void;
}

/**
 * Inline WebAuthn registration during sign-in (pre-auth guarded server-side): register a passkey
 * / security key (attestation), then immediately run the standard assertion ceremony to finish
 * signing in — registration alone cannot complete the session, since login needs an
 * origin-bound assertion ("second touch").
 */
export default function WebauthnRegistrationForm(props: Readonly<WebauthnRegistrationFormProps>) {
  const { t } = useTranslation();
  const apiRoot = useApiRoot();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const supported = isWebauthnSupported();

  const fail = (mfaError: MfaError) => {
    const { key, interpolation } = convertErrorArgsToInterpolation(mfaError);
    setError(t(key, interpolation));
  };

  /** Register (create) then sign in (get): two authenticator interactions, one flow. */
  const registerAndSignIn = async () => {
    setBusy(true);
    setError("");
    try {
      const start = await startRegistrationWebauthn(apiRoot);
      if (!start.success) {
        fail(start.error);
        return;
      }
      const attestation = await createCredential(start.creationOptionsJson);
      const finish = await finishRegistrationWebauthn(apiRoot, attestation);
      if (!finish.success) {
        fail(finish.error);
        return;
      }
      // Registration done — now the standard login ceremony against the new credential.
      const prepare = await prepareWebauthnFactor(apiRoot);
      if (!prepare.success || !prepare.requestOptionsJson) {
        fail(prepare.success ? { code: "unexpected_error" } : prepare.error);
        return;
      }
      const assertion = await getAssertion(prepare.requestOptionsJson);
      const verify = await verifyWebauthnFactor(apiRoot, assertion);
      if (verify.success) {
        props.onComplete(verify.remainingFactors);
      } else if (verify.fatalError) {
        props.onFatalError(verify.error);
      } else {
        fail(verify.error);
      }
    } catch (e) {
      // NotAllowedError = user cancelled / timed out.
      setError(
        t(
          (e as DOMException)?.name === "NotAllowedError"
            ? "factor.webauthn.cancelled"
            : "enroll.webauthn.failed",
        ),
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className={classes.otpFormWrapper}>
      <h2>
        <Trans i18nKey="enroll.webauthn.title" />
      </h2>
      {supported ? (
        <>
          <p className={classes.helpText}>
            <Trans i18nKey="enroll.webauthn.help" />
          </p>
          <ErrorMessage message={error} />
          <div style={{ textAlign: "center", marginTop: "0.5rem" }}>
            <button
              type="button"
              disabled={busy}
              aria-busy={busy}
              data-testid="enroll-webauthn-register"
              className={classes.submitButton}
              onClick={registerAndSignIn}
            >
              {busy ? t("factor.webauthn.inProgress") : t("enroll.webauthn.register")}
            </button>
          </div>
        </>
      ) : (
        <p className={classes.helpText} role="alert" data-testid="webauthn-unsupported">
          <Trans i18nKey="factor.webauthn.unsupported" />
        </p>
      )}
    </div>
  );
}
