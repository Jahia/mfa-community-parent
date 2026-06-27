import classes from "./component.module.css";

export default function ErrorMessage({
  message,
  id,
}: Readonly<{ message: string; id?: string }>) {
  return (
    <div className={classes.errorMessage} id={id}>
      {message && (
        <p role="alert" data-testid="error-message">
          {message}
        </p>
      )}
    </div>
  );
}
