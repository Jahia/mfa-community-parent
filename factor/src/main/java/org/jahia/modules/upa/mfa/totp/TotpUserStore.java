package org.jahia.modules.upa.mfa.totp;

import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRTemplate;
import org.jahia.services.content.decorator.JCRUserNode;
import org.jahia.services.usermanager.JahiaUserManagerService;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.RepositoryException;
import javax.jcr.Value;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Reads and writes the {@code upaTotp:userSettings} mixin on user nodes via a JCR system session.
 * <p>
 * Centralizes all JCR access for the TOTP factor — providers and mutations never touch JCR
 * directly. All writes go through a system session so {@code protected} properties can be
 * modified by the module itself.
 */
@Component(service = TotpUserStore.class, immediate = true)
public class TotpUserStore {

    private static final Logger logger = LoggerFactory.getLogger(TotpUserStore.class);

    public static final String MIXIN_USER_SETTINGS = "upaTotp:userSettings";
    public static final String PROP_SECRET = "upaTotp:secret";
    public static final String PROP_ENROLLED = "upaTotp:enrolled";
    public static final String PROP_LAST_USED_COUNTER = "upaTotp:lastUsedCounter";
    public static final String PROP_BACKUP_CODES = "upaTotp:backupCodes";

    private JahiaUserManagerService userManagerService;

    @Reference
    public void setUserManagerService(JahiaUserManagerService userManagerService) {
        this.userManagerService = userManagerService;
    }

    /**
     * Snapshot of the stored TOTP user settings.
     */
    public static class TotpUserSettings {
        private final boolean enrolled;
        private final String secretBase32;
        private final long lastUsedCounter;
        private final List<String> backupCodeHashes;

        public TotpUserSettings(boolean enrolled, String secretBase32, long lastUsedCounter,
                                List<String> backupCodeHashes) {
            this.enrolled = enrolled;
            this.secretBase32 = secretBase32;
            this.lastUsedCounter = lastUsedCounter;
            this.backupCodeHashes = backupCodeHashes == null
                    ? Collections.emptyList() : Collections.unmodifiableList(new ArrayList<>(backupCodeHashes));
        }

        public boolean isEnrolled() { return enrolled; }
        public String getSecretBase32() { return secretBase32; }
        public long getLastUsedCounter() { return lastUsedCounter; }
        public List<String> getBackupCodeHashes() { return backupCodeHashes; }
    }

    /**
     * Lightweight check that the user is enrolled in TOTP. Reads only the enrolled flag and
     * never loads the secret into the heap.
     */
    public boolean isEnrolled(String userId) throws RepositoryException {
        return Boolean.TRUE.equals(JCRTemplate.getInstance().doExecuteWithSystemSession(systemSession -> {
            JCRUserNode user = userManagerService.lookupUser(userId, systemSession);
            if (user == null || !user.isNodeType(MIXIN_USER_SETTINGS)) {
                return false;
            }
            return user.hasProperty(PROP_ENROLLED) && user.getProperty(PROP_ENROLLED).getBoolean();
        }));
    }

    /**
     * Load the user's TOTP settings or return an empty (not-enrolled) snapshot.
     */
    public TotpUserSettings load(String userId) throws RepositoryException {
        return JCRTemplate.getInstance().doExecuteWithSystemSession(systemSession -> {
            JCRUserNode user = userManagerService.lookupUser(userId, systemSession);
            if (user == null || !user.isNodeType(MIXIN_USER_SETTINGS)) {
                return new TotpUserSettings(false, null, 0L, Collections.emptyList());
            }
            boolean enrolled = user.hasProperty(PROP_ENROLLED) && user.getProperty(PROP_ENROLLED).getBoolean();
            String secret = user.hasProperty(PROP_SECRET) ? user.getProperty(PROP_SECRET).getString() : null;
            long counter = user.hasProperty(PROP_LAST_USED_COUNTER) ? user.getProperty(PROP_LAST_USED_COUNTER).getLong() : 0L;
            List<String> hashes = new ArrayList<>();
            if (user.hasProperty(PROP_BACKUP_CODES)) {
                Value[] values = user.getProperty(PROP_BACKUP_CODES).getValues();
                for (Value v : values) {
                    hashes.add(v.getString());
                }
            }
            return new TotpUserSettings(enrolled, secret, counter, hashes);
        });
    }

    /**
     * Persist a freshly-confirmed enrollment in a SINGLE JCR transaction: applies the mixin
     * if missing, sets secret, marks enrolled, stores backup-code hashes, AND sets
     * {@code lastUsedCounter} to the matched counter so the very code used to confirm
     * enrollment cannot be replayed at login.
     */
    public void saveEnrollment(String userId, String secretBase32, List<String> backupCodeHashes,
                               long matchedCounter) throws RepositoryException {
        JCRTemplate.getInstance().doExecuteWithSystemSession(systemSession -> {
            JCRUserNode user = userManagerService.lookupUser(userId, systemSession);
            if (user == null) {
                throw new RepositoryException("User not found: " + userId);
            }
            ensureMixin(user);
            user.setProperty(PROP_SECRET, secretBase32);
            user.setProperty(PROP_ENROLLED, true);
            user.setProperty(PROP_LAST_USED_COUNTER, matchedCounter);
            user.setProperty(PROP_BACKUP_CODES, backupCodeHashes.toArray(new String[0]));
            systemSession.save();
            logger.info("TOTP enrollment persisted for user {}", user.getName());
            return null;
        });
    }

    /**
     * Atomically verify a submitted TOTP code AND consume the matched counter in a SINGLE
     * JCR transaction. This is the chokepoint used by both the login-time verify path
     * ({@link TotpFactorProvider}) and the management mutations ({@code TotpFactorMutation}).
     * <p>
     * Reads {@code lastUsedCounter} and the secret from the (system) session, runs the
     * code through {@link TotpService#verifyCode}, and on success persists the matched
     * counter in the same transaction — guaranteeing that the same code cannot be replayed
     * by a concurrent / subsequent call.
     *
     * @return the matched counter on success, empty on rejection (no match, replay,
     *         or not enrolled)
     */
    public Optional<Long> verifyAndConsumeTotp(String userId, TotpService totpService,
                                               String submittedCode, long nowSeconds,
                                               int driftWindows) throws RepositoryException {
        return JCRTemplate.getInstance().doExecuteWithSystemSession(systemSession -> {
            JCRUserNode user = userManagerService.lookupUser(userId, systemSession);
            if (user == null || !user.isNodeType(MIXIN_USER_SETTINGS)) {
                return Optional.<Long>empty();
            }
            boolean enrolled = user.hasProperty(PROP_ENROLLED) && user.getProperty(PROP_ENROLLED).getBoolean();
            if (!enrolled || !user.hasProperty(PROP_SECRET)) {
                return Optional.<Long>empty();
            }
            String secretBase32 = user.getProperty(PROP_SECRET).getString();
            long lastUsed = user.hasProperty(PROP_LAST_USED_COUNTER)
                    ? user.getProperty(PROP_LAST_USED_COUNTER).getLong() : 0L;
            byte[] secret = totpService.fromBase32(secretBase32);
            Optional<Long> matched = totpService.verifyCode(secret, submittedCode, nowSeconds,
                    lastUsed, driftWindows);
            if (!matched.isPresent()) {
                return Optional.<Long>empty();
            }
            // Persist the consumed counter atomically before returning success.
            user.setProperty(PROP_LAST_USED_COUNTER, matched.get());
            systemSession.save();
            return matched;
        });
    }

    /**
     * Update the last-used counter (replay protection).
     */
    public void updateLastUsedCounter(String userId, long counter) throws RepositoryException {
        JCRTemplate.getInstance().doExecuteWithSystemSession(systemSession -> {
            JCRUserNode user = userManagerService.lookupUser(userId, systemSession);
            if (user == null || !user.isNodeType(MIXIN_USER_SETTINGS)) {
                return null;
            }
            user.setProperty(PROP_LAST_USED_COUNTER, counter);
            systemSession.save();
            return null;
        });
    }

    /**
     * Remove a single backup-code hash by index (single-use consumption).
     */
    public void consumeBackupCode(String userId, int index) throws RepositoryException {
        JCRTemplate.getInstance().doExecuteWithSystemSession(systemSession -> {
            JCRUserNode user = userManagerService.lookupUser(userId, systemSession);
            if (user == null || !user.hasProperty(PROP_BACKUP_CODES)) {
                return null;
            }
            Value[] values = user.getProperty(PROP_BACKUP_CODES).getValues();
            if (index < 0 || index >= values.length) {
                return null;
            }
            List<String> remaining = new ArrayList<>(values.length - 1);
            for (int i = 0; i < values.length; i++) {
                if (i != index) {
                    remaining.add(values[i].getString());
                }
            }
            user.setProperty(PROP_BACKUP_CODES, remaining.toArray(new String[0]));
            systemSession.save();
            logger.info("Backup code consumed for user {} (remaining: {})", user.getName(), remaining.size());
            return null;
        });
    }

    /**
     * Replace the entire backup-code list (used on regeneration).
     */
    public void replaceBackupCodes(String userId, List<String> newHashes) throws RepositoryException {
        JCRTemplate.getInstance().doExecuteWithSystemSession(systemSession -> {
            JCRUserNode user = userManagerService.lookupUser(userId, systemSession);
            if (user == null) {
                throw new RepositoryException("User not found: " + userId);
            }
            ensureMixin(user);
            user.setProperty(PROP_BACKUP_CODES, newHashes.toArray(new String[0]));
            systemSession.save();
            return null;
        });
    }

    /**
     * Disable TOTP for the user: removes the secret, clears backup codes, marks not enrolled.
     */
    public void disable(String userId) throws RepositoryException {
        JCRTemplate.getInstance().doExecuteWithSystemSession(systemSession -> {
            JCRUserNode user = userManagerService.lookupUser(userId, systemSession);
            if (user == null || !user.isNodeType(MIXIN_USER_SETTINGS)) {
                return null;
            }
            if (user.hasProperty(PROP_SECRET)) {
                user.getProperty(PROP_SECRET).remove();
            }
            if (user.hasProperty(PROP_BACKUP_CODES)) {
                user.getProperty(PROP_BACKUP_CODES).remove();
            }
            user.setProperty(PROP_ENROLLED, false);
            user.setProperty(PROP_LAST_USED_COUNTER, 0L);
            systemSession.save();
            logger.info("TOTP disabled for user {}", user.getName());
            return null;
        });
    }

    private static void ensureMixin(JCRNodeWrapper user) throws RepositoryException {
        if (!user.isNodeType(MIXIN_USER_SETTINGS)) {
            user.addMixin(MIXIN_USER_SETTINGS);
        }
    }
}
