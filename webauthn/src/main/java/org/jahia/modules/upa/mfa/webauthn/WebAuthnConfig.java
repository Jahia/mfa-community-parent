package org.jahia.modules.upa.mfa.webauthn;

import org.apache.commons.lang3.StringUtils;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Relying-Party configuration for the WebAuthn factor (PID {@code org.jahia.modules.webauthn}).
 * <p>
 * WebAuthn ceremonies are bound to a <b>Relying Party ID</b> (an effective domain, e.g.
 * {@code localhost} or {@code example.com}) and validated against a set of allowed
 * <b>origins</b> (scheme + host + port). These MUST match the domain the browser is actually
 * on; WebAuthn additionally requires a secure context (HTTPS) except on {@code localhost}.
 * Hot-reloaded via {@code @Modified} so an operator can adjust them without a restart.
 */
@Component(service = WebAuthnConfig.class, immediate = true, configurationPid = "org.jahia.modules.webauthn")
@Designate(ocd = WebAuthnConfig.Config.class)
public class WebAuthnConfig {

    private static final Logger logger = LoggerFactory.getLogger(WebAuthnConfig.class);

    @ObjectClassDefinition(name = "MFA WebAuthn factor")
    public @interface Config {
        @AttributeDefinition(name = "Relying Party ID",
                description = "Effective domain the credentials are scoped to (e.g. localhost or example.com). "
                        + "Must be a registrable suffix of the browsing origin's host.")
        String rpId() default "localhost";

        @AttributeDefinition(name = "Relying Party display name",
                description = "Human-readable site name shown by the authenticator during registration.")
        String rpName() default "Jahia";

        @AttributeDefinition(name = "Allowed origins",
                description = "Full origins (scheme://host[:port]) permitted in ceremonies, e.g. "
                        + "https://example.com. Leave empty to let the library derive it from the RP ID.")
        String[] origins() default {};
    }

    private volatile String rpId;
    private volatile String rpName;
    private volatile Set<String> origins;

    @Activate
    @Modified
    public void activate(Config config) {
        this.rpId = StringUtils.defaultIfBlank(config.rpId(), "localhost").trim();
        this.rpName = StringUtils.defaultIfBlank(config.rpName(), "Jahia").trim();
        this.origins = config.origins() == null ? Collections.emptySet()
                : Arrays.stream(config.origins())
                    .map(StringUtils::trimToNull)
                    .filter(o -> o != null)
                    .collect(Collectors.toCollection(LinkedHashSet::new));
        logger.info("WebAuthn factor configured (rpId={}, rpName={}, origins={})", rpId, rpName, origins);
    }

    public String getRpId() {
        return rpId;
    }

    public String getRpName() {
        return rpName;
    }

    /** Allowed origins; empty means "derive from the RP ID". */
    public Set<String> getOrigins() {
        return origins == null ? Collections.emptySet() : Collections.unmodifiableSet(origins);
    }
}
