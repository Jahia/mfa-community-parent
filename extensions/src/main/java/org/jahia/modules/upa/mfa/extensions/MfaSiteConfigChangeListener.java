package org.jahia.modules.upa.mfa.extensions;

/**
 * Notified whenever the per-site MFA configuration changes (a {@code .cfg} is delivered, replayed,
 * removed, or saved through {@link MfaSiteConfigService}). It lets a consumer that caches a
 * configuration-derived answer drop that cache promptly instead of serving a stale one.
 * <p>
 * <b>Why this exists (U8 / the ≤60&nbsp;s fail-open):</b> {@code MfaLoginGateDecision} caches the
 * "is any site enforcing MFA?" answer for a minute to keep the unauthenticated {@code /cms/login}
 * gate cheap. Before this callback, that cache was invalidated only on provider bind/unbind and the
 * decision's own {@code @Activate}/{@code @Modified} — <b>never</b> when an admin enabled a factor
 * on the first site via a {@code .cfg}. That left a bounded window where the gate still served the
 * cached "not enforcing" answer and authenticated password-only: a fail-OPEN in a security gate.
 * Having {@link MfaSiteConfigService} fire this callback on every config change closes the window.
 * <p>
 * <b>OSGi wiring:</b> {@code MfaLoginGateDecision} (which implements this) already {@code @Reference}s
 * {@link MfaSiteConfigService} for its readiness flag, so the reverse edge — the config service
 * calling listeners — MUST be an <em>optional/dynamic</em> reference to avoid an activation cycle.
 * The config service therefore binds listeners dynamically and no-ops when none is present; it never
 * depends on a listener to activate.
 */
public interface MfaSiteConfigChangeListener {

    /**
     * Called after the per-site configuration has changed. Implementations must be cheap and
     * non-blocking (it runs on the config-write path): drop a cached snapshot, do not perform I/O.
     */
    void onSiteConfigChanged();
}
