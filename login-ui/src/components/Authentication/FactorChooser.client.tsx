import type { RefObject } from "react";
import { Trans, useTranslation } from "react-i18next";
import classes from "./component.module.css";

interface FactorChooserProps {
  factors: string[];
  onSelect: (factor: string) => void;
  /** Focus target for step-change focus management (WCAG 2.4.3). */
  headingRef?: RefObject<HTMLHeadingElement | null>;
}

/**
 * Renders a button per available factor. Used only when initiate() reports more than
 * one remaining factor — with a single factor, Authentication.client.tsx skips this
 * step and dispatches straight to the matching verification form.
 *
 * Currently recognises `totp` and `email_code`. Any other factor falls back to a
 * generic label keyed on the factor name (so a new factor type added to UPA shows up
 * with a usable button even before localisation is in place).
 */
export default function FactorChooser({
  factors,
  onSelect,
  headingRef,
}: Readonly<FactorChooserProps>) {
  const { t } = useTranslation();

  /** Converts a raw factor id (e.g. "email_code") to a readable title-case label. */
  const humanise = (id: string): string =>
    id
      .split("_")
      .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
      .join(" ");

  const labelFor = (factor: string): string => {
    switch (factor) {
      case "totp":
        return t("factorChooser.totp");
      case "email_code":
        return t("factorChooser.email_code");
      case "webauthn":
        return t("factorChooser.webauthn");
      default:
        // Fall back to a readable humanised label so unknown factor ids never appear
        // verbatim in the UI (WCAG 3.1.1 / SC 3.1.4 understandable content).
        return t(`factorChooser.${factor}`, { defaultValue: humanise(factor) });
    }
  };

  return (
    <div className={classes.otpFormWrapper}>
      <h2 ref={headingRef} tabIndex={-1}>
        <Trans i18nKey="factorChooser.title" />
      </h2>
      <p className={classes.helpText}>
        <Trans i18nKey="factorChooser.description" />
      </p>
      <div
        role="group"
        aria-label={t("factorChooser.title")}
        style={{ display: "flex", flexDirection: "column", gap: "0.75rem", marginTop: "1rem" }}
      >
        {factors.map((factor) => (
          <button
            key={factor}
            type="button"
            data-testid={`factor-choose-${factor}`}
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
