import { useTranslation } from "react-i18next";
import classes from "./component.module.css";

interface ChangeMethodButtonProps {
  /** Invoked to leave the current form and return to the chooser. */
  onClick: () => void;
  /** i18n key for the control label. */
  labelKey: string;
  testId: string;
}

/**
 * Persistent "go back to the chooser" control rendered on a verification or enrollment form when
 * the user had more than one method to choose from. Without it a wrong-factor pick or an
 * unavailable device is a dead end. Styled as the existing underline link control (.toggleMode).
 */
export default function ChangeMethodButton({
  onClick,
  labelKey,
  testId,
}: Readonly<ChangeMethodButtonProps>) {
  const { t } = useTranslation();
  return (
    <button type="button" className={classes.toggleMode} data-testid={testId} onClick={onClick}>
      {t(labelKey)}
    </button>
  );
}
