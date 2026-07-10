package pt.henrique.serverauth.storage;

import java.time.Instant;

public record UserRecord(
        long id,
        String usernameLower,
        String usernameOriginal,
        String passwordHash,
        Instant registrationTime,
        Instant lastLoginTime,
        String lastIp,
        boolean autologinEnabled,
        String trustedIp1,
        long trustedIp1Score,
        String trustedIp2,
        long trustedIp2Score,
        String recoveryQuestion,
        String recoveryAnswerHash,
        int loginAttempts,
        Instant loginLockoutUntil,
        int recoveryAttempts,
        Instant recoveryLockoutUntil,
        Instant lastSessionTime,
        // 2FA fields
        boolean twoFactorEnabled,
        String totpSecret,
        String backupCodesJson,
        Instant lastTwoFactorSuccess,
        int twoFactorAttempts,
        Instant twoFactorLockoutUntil,
        boolean twoFactorRequired,
        String last2faVerifiedIp,
        // Last logout location (format: world,x,y,z,yaw,pitch)
        String lastLogoutLocation,
        // UUID + client fingerprint fields (V5)
        String uuid,
        String clientBrand,
        String clientSettingsHash,
        String lastClientFingerprint
) {

    public boolean isRegistered() {
        return passwordHash != null && !passwordHash.isBlank();
    }

    public boolean hasRecovery() {
        return recoveryQuestion != null && !recoveryQuestion.isBlank()
                && recoveryAnswerHash != null && !recoveryAnswerHash.isBlank();
    }

    public boolean has2FA() {
        return twoFactorEnabled && totpSecret != null && !totpSecret.isBlank();
    }
}
