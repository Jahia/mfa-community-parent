package org.jahia.modules.upa.mfa.totp;

import org.jahia.modules.upa.mfa.extensions.SkippablePreparation;

import java.io.Serializable;

/**
 * Marker preparation result. TOTP has nothing to deliver to the user during {@code prepare}
 * (the authenticator app generates codes locally) — this no-op marker exists only so the
 * {@code MfaFactorState} keeps a non-null preparation result and {@code isPrepared()} is true.
 * <p>
 * When {@code skipped} is true, the site has TOTP disabled (or the user is not enrolled
 * AND the site does not enforce enrollment). In that case {@link TotpFactorProvider#verify}
 * accepts ANY submission — the UI is expected not to render a TOTP step at all, but this
 * is a defensive backstop so a misconfigured client doesn't get stuck.
 */
public class TotpPreparationResult implements Serializable, SkippablePreparation {
    private static final long serialVersionUID = 2L;
    private final boolean skipped;

    public TotpPreparationResult() {
        this(false);
    }

    public TotpPreparationResult(boolean skipped) {
        this.skipped = skipped;
    }

    @Override
    public boolean isSkipped() {
        return skipped;
    }
}
