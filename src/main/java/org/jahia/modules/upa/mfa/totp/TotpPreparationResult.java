package org.jahia.modules.upa.mfa.totp;

import java.io.Serializable;

/**
 * Marker preparation result. TOTP has nothing to deliver to the user during {@code prepare}
 * (the authenticator app generates codes locally) — this no-op marker exists only so the
 * {@code MfaFactorState} keeps a non-null preparation result and {@code isPrepared()} is true.
 */
public class TotpPreparationResult implements Serializable {
    private static final long serialVersionUID = 1L;
    public TotpPreparationResult() {
        // marker
    }
}
