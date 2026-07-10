package pt.henrique.serverauth.storage;

import java.time.Instant;
import java.util.Optional;

public interface UserRepository {

    Optional<UserRecord> findByUsernameLower(String usernameLower);

    /** Number of accounts whose last known IP equals the given IP. Used to enforce max-accounts-per-ip. */
    int countAccountsByIp(String ip);

    UserRecord createUser(String usernameOriginal, String usernameLower, String passwordHash, Instant now);

    boolean updatePasswordHash(long userId, String passwordHash, Instant now);

    boolean updateLastLogin(long userId, Instant now, String ip);

    boolean setAutoLoginEnabled(long userId, boolean enabled, Instant now);

    boolean updateTrustedIpScore(long userId, String ip, Instant now);

    boolean setRecoveryQuestion(long userId, String question, Instant now);

    boolean setRecoveryAnswerHash(long userId, String answerHash, Instant now);

    boolean resetLoginAttempts(long userId, Instant now);

    boolean incrementLoginAttempts(long userId, int maxAttempts, Instant lockoutUntil, Instant now);

    boolean resetRecoveryAttempts(long userId, Instant now);

    boolean incrementRecoveryAttempts(long userId, int maxAttempts, Instant lockoutUntil, Instant now);

    boolean updateLastSessionTime(long userId, Instant now);

    // 2FA methods
    boolean setTotpSecret(long userId, String secret, Instant now);

    boolean setBackupCodes(long userId, String codesJson, Instant now);

    boolean setTwoFactorEnabled(long userId, boolean enabled, Instant now);

    boolean updateLastTwoFactorSuccess(long userId, Instant now);

    boolean resetTwoFactorAttempts(long userId, Instant now);

    boolean incrementTwoFactorAttempts(long userId, int maxAttempts, Instant lockoutUntil, Instant now);

    boolean setTwoFactorRequired(long userId, boolean required, Instant now);

    boolean updateLast2faVerifiedIp(long userId, String ip, Instant now);

    boolean updateLastLogoutLocation(long userId, String location, Instant now);

    boolean deleteUser(long userId);

    Optional<UserRecord> findByUuid(String uuid);

    // UUID + fingerprint methods (V5)
    boolean updateUuid(long userId, String uuid);

    boolean updateClientFingerprint(long userId, String clientBrand, String clientSettingsHash, String fingerprint);
}
