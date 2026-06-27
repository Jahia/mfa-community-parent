import { type ChangeEvent, type FormEvent, useEffect, useRef, useState } from "react";
import { useApiRoot } from "../../hooks/ApiRootContext";
import { prepareEmailFactor, verifyEmailCodeFactor } from "../../services";
import classes from "./component.module.css";
import ErrorMessage from "./ErrorMessage.client";
import { translateError } from "../../services/i18n";
import { Trans, useTranslation } from "react-i18next";
import type { MfaError } from "../../services/common";
import { submitOnEnter } from "./formKeyboard";
import ChangeMethodButton from "./ChangeMethodButton.client";

interface EmailCodeVerificationFormProps {
  onSuccess: (remainingFactors: string[]) => void;
  onFatalError: (error: MfaError) => void;
  /** When set, render a "Use a different method" control returning to the factor chooser. */
  onChangeMethod?: () => void;
}

const CODE_LENGTH = 6;

export default function EmailCodeVerificationForm(
  props: Readonly<EmailCodeVerificationFormProps>,
) {
  const { t } = useTranslation();
  const apiRoot = useApiRoot();
  const inputRef = useRef<HTMLInputElement>(null);
  const [loading, setLoading] = useState(true);
  // Distinguishes the very first send (full-screen spinner) from a user-triggered resend
  // (in-place sending state + confirmation), so the spinner copy is honest about what's happening.
  const [resending, setResending] = useState(false);
  const [resentConfirmation, setResentConfirmation] = useState("");
  const [maskedEmail, setMaskedEmail] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const prepare = (isResend = false) => {
    if (isResend) {
      setResending(true);
      setResentConfirmation("");
    } else {
      setLoading(true);
    }
    prepareEmailFactor(apiRoot)
      .then((result) => {
        if (result.success) {
          setError("");
          setMaskedEmail(result.maskedEmail);
          if (isResend) {
            setResentConfirmation(t("factor.email_code.resent", { maskedEmail: result.maskedEmail }));
          }
        } else if (result?.fatalError) {
          props.onFatalError(result.error);
        } else {
          setError(translateError(t, result.error));
        }
      })
      .finally(() => {
        setLoading(false);
        setResending(false);
      });
  };

  useEffect(() => {
    prepare();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Focus the code field once the form is interactive (item 4 parity: effect, not setTimeout).
  useEffect(() => {
    if (!loading) {
      inputRef.current?.focus();
    }
  }, [loading]);

  if (loading) {
    return (
      <div role="status" aria-live="polite">
        <Trans i18nKey="factor.email_code.sending" />
      </div>
    );
  }

  const handleCodeChange = (e: ChangeEvent<HTMLInputElement>) => {
    setCode(e.target.value.replace(/\D/g, "").slice(0, CODE_LENGTH));
  };

  const submit = () => {
    if (code.length !== CODE_LENGTH || submitting) return;
    setSubmitting(true);
    verifyEmailCodeFactor(apiRoot, code)
      .then((result) => {
        if (result.success) {
          setError("");
          props.onSuccess(result.remainingFactors);
        } else if (result?.fatalError) {
          props.onFatalError(result.error);
        } else {
          setError(translateError(t, result.error));
        }
      })
      .finally(() => setSubmitting(false));
  };

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    submit();
  };

  return (
    <div className={classes.otpFormWrapper}>
      <h2>
        <Trans i18nKey="factor.email_code.title" />
      </h2>
      {maskedEmail && (
        <p className={classes.helpText}>
          <Trans
            i18nKey="factor.email_code.verification_code_has_been_sent"
            components={{ mark: <strong /> }}
            values={{ maskedEmail }}
          />
        </p>
      )}
      <form onSubmit={handleSubmit}>
        <div style={{ textAlign: "center" }}>
          <input
            ref={inputRef}
            id="emailVerificationCode"
            name="emailVerificationCode"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            placeholder="123456"
            value={code}
            onChange={handleCodeChange}
            onKeyDown={submitOnEnter(submit)}
            aria-label={t("factor.email_code.codeInputLabel")}
            aria-describedby="emailCode-error"
            data-testid="email-verification-code"
            className={classes.otpInput}
            required
          />
        </div>
        <ErrorMessage message={error} id="emailCode-error" />
        {/* Confirmation after a successful resend, announced to assistive tech (item 12). */}
        <div role="status" aria-live="polite" className={classes.helpText} data-testid="email-resent">
          {resentConfirmation}
        </div>
        <div style={{ textAlign: "center", marginTop: "0.5rem" }}>
          <button
            type="submit"
            disabled={code.length !== CODE_LENGTH || submitting}
            aria-busy={submitting}
            aria-describedby="emailCode-error"
            data-testid="email-verification-submit"
            className={classes.submitButton}
          >
            <Trans i18nKey="factor.email_code.verify" />
          </button>
        </div>
        <hr aria-hidden="true" />
        <div className={classes.additionalAction}>
          <button
            type="button"
            className={classes.toggleMode}
            data-testid="email-resend"
            disabled={resending}
            aria-busy={resending}
            onClick={() => prepare(true)}
          >
            {resending ? (
              <Trans i18nKey="factor.email_code.sending" />
            ) : (
              <Trans i18nKey="factor.email_code.resend" />
            )}
          </button>
          {props.onChangeMethod && (
            <div style={{ marginTop: "0.5rem" }}>
              <ChangeMethodButton
                onClick={props.onChangeMethod}
                labelKey="chooser.useDifferentMethod"
                testId="change-method"
              />
            </div>
          )}
        </div>
      </form>
    </div>
  );
}
