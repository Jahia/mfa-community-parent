package org.jahia.modules.upa.mfa.extensions;

/**
 * Contract for factor preparation results that can represent a pick-one SKIP marker instead of a
 * real challenge. Factor providers consult their siblings' preparation results through this
 * interface when evaluating the "another enforced factor already verified in-session" pick-one
 * row: a factor whose preparation was skipped was never actually challenged — its verified flag
 * only records the client draining the step — so it must NOT satisfy pick-one for its siblings.
 * <p>
 * Without this distinction, two enforced factors can skip-drain each other circularly: factor A
 * skips because factor B is configured for the user ("they will verify with that one"), the
 * client drains A as verified, then factor B skips because A is "already verified" — and the
 * session completes without any second-factor challenge at all.
 */
public interface SkippablePreparation {

    /** Whether this preparation is a skip marker rather than a real challenge. */
    boolean isSkipped();
}
