import { type ChangeEvent, type FormEvent, useEffect, useRef, useState } from "react";
import { QRCodeCanvas } from "qrcode.react";
import { Trans, useTranslation } from "react-i18next";
import { useApiRoot } from "../../hooks/ApiRootContext";
import { confirmEnrollTotp, enrollTotp } from "../../services";
import classes from "./component.module.css";
import ErrorMessage from "./ErrorMessage.client";
import { convertErrorArgsToInterpolation } from "../../services/i18n";
import type { MfaError } from "../../services/common";
import { submitOnEnter } from "./formKeyboard";

interface TotpEnrollmentFormProps {
  onComplete: (remainingFactors: string[]) => void;
  onFatalError: (error: MfaError) => void;
}

const TOTP_CODE_LENGTH = 6;

type Phase = "loading" | "setup" | "backupCodes";

/**
 * Inline TOTP enrollment during sign-in: the server generated a fresh secret for the MFA-session
 * user (pre-auth guarded); scan the QR (or copy the secret), confirm with the first authenticator
 * code — the server persists the enrollment AND verifies the code in the same request — then
 * acknowledge the one-shot backup codes to finish signing in.
 */
export default function TotpEnrollmentForm(props: Readonly<TotpEnrollmentFormProps>) {
  const { t } = useTranslation();
  const apiRoot = useApiRoot();
  const [phase, setPhase] = useState<Phase>("loading");
  const [secret, setSecret] = useState("");
  const [otpauthUri, setOtpauthUri] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const remainingRef = useRef<string[]>([]);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    enrollTotp(apiRoot)
      .then((result) => {
        if (result.success) {
          setSecret(result.secret);
          setOtpauthUri(result.otpauthUri);
          setPhase("setup");
          setTimeout(() => inputRef.current?.focus(), 0);
        } else {
          props.onFatalError(result.error);
        }
      })
      .catch(() => props.onFatalError({ code: "unexpected_error" }));
    // Intentionally run once on mount.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleCodeInputChange = (e: ChangeEvent<HTMLInputElement>) => {
    setCode(e.target.value.replace(/\D/g, "").slice(0, TOTP_CODE_LENGTH));
  };

  const isCodeValid = code.length === TOTP_CODE_LENGTH;

  const submit = () => {
    if (!isCodeValid || submitting) return;
    setSubmitting(true);
    confirmEnrollTotp(apiRoot, code)
      .then((result) => {
        if (result.success) {
          setError("");
          remainingRef.current = result.remainingFactors;
          setBackupCodes(result.backupCodes);
          setPhase("backupCodes");
        } else if (result?.fatalError) {
          props.onFatalError(result.error);
        } else {
          const { key, interpolation } = convertErrorArgsToInterpolation(result.error);
          setError(t(key, interpolation));
        }
      })
      .finally(() => setSubmitting(false));
  };

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    submit();
  };

  if (phase === "loading") {
    return (
      <div role="status" aria-live="polite">
        <Trans i18nKey="enroll.totp.loading" />
      </div>
    );
  }

  if (phase === "backupCodes") {
    return (
      <div className={classes.otpFormWrapper}>
        <h2>
          <Trans i18nKey="enroll.totp.backupTitle" />
        </h2>
        <p className={classes.helpText} role="alert">
          <Trans i18nKey="enroll.totp.backupWarning" />
        </p>
        <pre
          data-testid="enroll-backup-codes"
          style={{ textAlign: "center", lineHeight: 1.7, userSelect: "all" }}
        >
          {backupCodes.join("\n")}
        </pre>
        <div style={{ textAlign: "center", marginTop: "0.5rem" }}>
          <button
            type="button"
            data-testid="enroll-backup-ack"
            className={classes.submitButton}
            onClick={() => props.onComplete(remainingRef.current)}
          >
            {t("enroll.totp.backupAck")}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className={classes.otpFormWrapper}>
      <h2>
        <Trans i18nKey="enroll.totp.title" />
      </h2>
      <p className={classes.helpText}>
        <Trans i18nKey="enroll.totp.scan" />
      </p>
      <div style={{ textAlign: "center", margin: "1rem 0" }}>
        <QRCodeCanvas value={otpauthUri} size={224} level="M" data-testid="enroll-qr" />
      </div>
      <p className={classes.helpText}>
        <Trans i18nKey="enroll.totp.secretLabel" />
      </p>
      <p style={{ textAlign: "center", userSelect: "all", overflowWrap: "anywhere" }}>
        <code data-testid="enroll-secret">{secret}</code>
      </p>
      <form onSubmit={handleSubmit}>
        <p className={classes.helpText}>
          <Trans i18nKey="enroll.totp.codeLabel" />
        </p>
        <div style={{ textAlign: "center" }}>
          <input
            ref={inputRef}
            id="enrollCode"
            name="enrollCode"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            placeholder="123456"
            value={code}
            onChange={handleCodeInputChange}
            onKeyDown={submitOnEnter(submit)}
            aria-label={t("enroll.totp.codeLabel")}
            data-testid="enroll-code-input"
            className={classes.otpInput}
            required
          />
        </div>
        <ErrorMessage message={error} />
        <div style={{ textAlign: "center", marginTop: "0.5rem" }}>
          <button
            type="submit"
            disabled={!isCodeValid || submitting}
            aria-busy={submitting}
            data-testid="enroll-confirm-btn"
            className={classes.submitButton}
          >
            {t("enroll.totp.confirm")}
          </button>
        </div>
      </form>
    </div>
  );
}
