import type { RefObject } from "react";
import { Trans, useTranslation } from "react-i18next";
import classes from "./component.module.css";

interface EnrollmentChooserProps {
  factors: string[];
  onSelect: (factor: string) => void;
  /** Focus target for step-change focus management (WCAG 2.4.3). */
  headingRef?: RefObject<HTMLHeadingElement | null>;
}

/**
 * Renders a button per factor the user may set up inline (enforcement is active but the user
 * has none of the enforced factors configured). Mirrors {@code FactorChooser} with
 * enrollment-specific labels; shown only when more than one factor is offered.
 */
export default function EnrollmentChooser({
  factors,
  onSelect,
  headingRef,
}: Readonly<EnrollmentChooserProps>) {
  const { t } = useTranslation();

  const labelFor = (factor: string): string => {
    switch (factor) {
      case "totp":
        return t("enroll.chooser.totp");
      case "webauthn":
        return t("enroll.chooser.webauthn");
      default:
        return factor;
    }
  };

  return (
    <div className={classes.otpFormWrapper}>
      <h2 ref={headingRef} tabIndex={-1}>
        <Trans i18nKey="enroll.chooser.title" />
      </h2>
      <p className={classes.helpText}>
        <Trans i18nKey="enroll.chooser.description" />
      </p>
      <div
        role="group"
        aria-label={t("enroll.chooser.title")}
        style={{ display: "flex", flexDirection: "column", gap: "0.75rem", marginTop: "1rem" }}
      >
        {factors.map((factor) => (
          <button
            key={factor}
            type="button"
            data-testid={`enroll-choose-${factor}`}
            className={classes.submitButton}
            onClick={() => onSelect(factor)}
          >
            {labelFor(factor)}
          </button>
        ))}
      </div>
    </div>
  );
}
