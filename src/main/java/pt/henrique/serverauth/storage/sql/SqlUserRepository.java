package pt.henrique.serverauth.storage.sql;

import pt.henrique.serverauth.config.PluginConfig.StorageType;
import pt.henrique.serverauth.storage.UserRecord;
import pt.henrique.serverauth.storage.UserRepository;
import pt.henrique.serverauth.util.IpUtil;

import javax.sql.DataSource;
import java.sql.*;
import java.time.Instant;
import java.util.Optional;

public final class SqlUserRepository implements UserRepository {

    private final DataSource ds;
    private final StorageType type;

    public SqlUserRepository(DataSource ds, StorageType type) {
        this.ds = ds;
        this.type = type;
    }

    @Override
    public Optional<UserRecord> findByUsernameLower(String usernameLower) {
        String sql = "SELECT * FROM auth_users WHERE username_lower=?";
        try (Connection c = ds.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, usernameLower);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return Optional.empty();
                return Optional.of(map(rs));
            }
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public int countAccountsByIp(String ip) {
        if (ip == null || ip.isBlank()) return 0;
        String sql = "SELECT COUNT(*) FROM auth_users WHERE last_ip=?";
        try (Connection c = ds.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, ip);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getInt(1) : 0;
            }
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public Optional<UserRecord> findByUuid(String uuid) {
        if (uuid == null || uuid.isBlank()) return Optional.empty();
        String sql = "SELECT * FROM auth_users WHERE uuid=?";
        try (Connection c = ds.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, uuid);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return Optional.empty();
                return Optional.of(map(rs));
            }
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public UserRecord createUser(String usernameOriginal, String usernameLower, String passwordHash, Instant now) {
        return createUser(usernameOriginal, usernameLower, passwordHash, now, null);
    }

    public UserRecord createUser(String usernameOriginal, String usernameLower, String passwordHash, Instant now, String uuid) {
        String sql = "INSERT INTO auth_users (username_lower, username_original, password_hash, registration_time, last_login_time, last_ip, autologin_enabled, trusted_ip_1, trusted_ip_1_score, trusted_ip_2, trusted_ip_2_score, recovery_question, recovery_answer_hash, login_attempts, login_lockout_until, recovery_attempts, recovery_lockout_until, last_session_time, two_factor_enabled, totp_secret, backup_codes_json, last_two_factor_success, two_factor_attempts, two_factor_lockout_until, two_factor_required, last_2fa_verified_ip, last_logout_location, uuid, client_brand, client_settings_hash, last_client_fingerprint) " +
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

        long ts = now.toEpochMilli();
        try (Connection c = ds.getConnection(); PreparedStatement ps = c.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, usernameLower);
            ps.setString(2, usernameOriginal);
            ps.setString(3, passwordHash);
            ps.setLong(4, ts);
            ps.setLong(5, ts);
            ps.setString(6, "");
            ps.setInt(7, 0);
            ps.setString(8, null);
            ps.setLong(9, 0);
            ps.setString(10, null);
            ps.setLong(11, 0);
            ps.setString(12, null);
            ps.setString(13, null);
            ps.setInt(14, 0);
            ps.setLong(15, 0);
            ps.setInt(16, 0);
            ps.setLong(17, 0);
            ps.setLong(18, 0);
            // 2FA defaults
            ps.setInt(19, 0);
            ps.setString(20, null);
            ps.setString(21, null);
            ps.setLong(22, 0);
            ps.setInt(23, 0);
            ps.setLong(24, 0);
            ps.setInt(25, 0);
            ps.setString(26, null);
            ps.setString(27, null);
            // UUID + fingerprint
            ps.setString(28, uuid);
            ps.setString(29, null);
            ps.setString(30, null);
            ps.setString(31, null);
            ps.executeUpdate();

            long id = 0;
            try (ResultSet keys = ps.getGeneratedKeys()) {
                if (keys.next()) id = keys.getLong(1);
            } catch (SQLException ignored) {
            }
            if (id == 0 && type == StorageType.SQLITE) {
                try (Statement st = c.createStatement(); ResultSet rs = st.executeQuery("SELECT last_insert_rowid()")) {
                    if (rs.next()) id = rs.getLong(1);
                }
            }

            return new UserRecord(id, usernameLower, usernameOriginal, passwordHash,
                    now, now, "", false,
                    null, 0, null, 0,
                    null, null,
                    0, Instant.EPOCH,
                    0, Instant.EPOCH,
                    Instant.EPOCH,
                    false, null, null, Instant.EPOCH,
                    0, Instant.EPOCH, false, null, null,
                    uuid, null, null, null);
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public boolean updatePasswordHash(long userId, String passwordHash, Instant now) {
        return update("UPDATE auth_users SET password_hash=?, last_login_time=? WHERE id=?", ps -> {
            ps.setString(1, passwordHash);
            ps.setLong(2, now.toEpochMilli());
            ps.setLong(3, userId);
        });
    }

    @Override
    public boolean updateLastLogin(long userId, Instant now, String ip) {
        return update("UPDATE auth_users SET last_login_time=?, last_ip=? WHERE id=?", ps -> {
            ps.setLong(1, now.toEpochMilli());
            ps.setString(2, ip == null ? "" : ip);
            ps.setLong(3, userId);
        });
    }

    @Override
    public boolean setAutoLoginEnabled(long userId, boolean enabled, Instant now) {
        return update("UPDATE auth_users SET autologin_enabled=?, last_login_time=? WHERE id=?", ps -> {
            ps.setInt(1, enabled ? 1 : 0);
            ps.setLong(2, now.toEpochMilli());
            ps.setLong(3, userId);
        });
    }

    @Override
    public boolean updateTrustedIpScore(long userId, String ip, Instant now) {
        if (ip == null || ip.isBlank()) return false;

        Optional<UserRecord> opt = findById(userId);
        if (opt.isEmpty()) return false;
        UserRecord u = opt.get();

        String ip1 = u.trustedIp1();
        String ip2 = u.trustedIp2();
        long s1 = u.trustedIp1Score();
        long s2 = u.trustedIp2Score();

        if (IpUtil.ipEquals(ip, ip1)) {
            s1++;
        } else if (IpUtil.ipEquals(ip, ip2)) {
            s2++;
        } else if (ip1 == null || ip1.isBlank()) {
            ip1 = ip;
            s1 = 1;
        } else if (ip2 == null || ip2.isBlank()) {
            ip2 = ip;
            s2 = 1;
        } else {
            // replace the lower score
            if (s1 <= s2) {
                ip1 = ip;
                s1 = 1;
            } else {
                ip2 = ip;
                s2 = 1;
            }
        }

        // keep canonical order (highest score first)
        if (s2 > s1) {
            String tmpIp = ip1; ip1 = ip2; ip2 = tmpIp;
            long tmpS = s1; s1 = s2; s2 = tmpS;
        }

        String finalIp1 = ip1;
        String finalIp2 = ip2;
        long finalS1 = s1;
        long finalS2 = s2;

        return update("UPDATE auth_users SET trusted_ip_1=?, trusted_ip_1_score=?, trusted_ip_2=?, trusted_ip_2_score=?, last_login_time=? WHERE id=?", ps -> {
            ps.setString(1, finalIp1);
            ps.setLong(2, finalS1);
            ps.setString(3, finalIp2);
            ps.setLong(4, finalS2);
            ps.setLong(5, now.toEpochMilli());
            ps.setLong(6, userId);
        });
    }

    @Override
    public boolean setRecoveryQuestion(long userId, String question, Instant now) {
        return update("UPDATE auth_users SET recovery_question=?, last_login_time=? WHERE id=?", ps -> {
            ps.setString(1, question);
            ps.setLong(2, now.toEpochMilli());
            ps.setLong(3, userId);
        });
    }

    @Override
    public boolean setRecoveryAnswerHash(long userId, String answerHash, Instant now) {
        return update("UPDATE auth_users SET recovery_answer_hash=?, last_login_time=? WHERE id=?", ps -> {
            ps.setString(1, answerHash);
            ps.setLong(2, now.toEpochMilli());
            ps.setLong(3, userId);
        });
    }

    @Override
    public boolean resetLoginAttempts(long userId, Instant now) {
        return update("UPDATE auth_users SET login_attempts=0, login_lockout_until=0, last_login_time=? WHERE id=?", ps -> {
            ps.setLong(1, now.toEpochMilli());
            ps.setLong(2, userId);
        });
    }

    @Override
    public boolean incrementLoginAttempts(long userId, int maxAttempts, Instant lockoutUntil, Instant now) {
        Optional<UserRecord> opt = findById(userId);
        if (opt.isEmpty()) return false;
        UserRecord u = opt.get();
        int attempts = u.loginAttempts() + 1;
        long lockout = attempts >= maxAttempts ? lockoutUntil.toEpochMilli() : 0;
        return update("UPDATE auth_users SET login_attempts=?, login_lockout_until=?, last_login_time=? WHERE id=?", ps -> {
            ps.setInt(1, attempts);
            ps.setLong(2, lockout);
            ps.setLong(3, now.toEpochMilli());
            ps.setLong(4, userId);
        });
    }

    @Override
    public boolean resetRecoveryAttempts(long userId, Instant now) {
        return update("UPDATE auth_users SET recovery_attempts=0, recovery_lockout_until=0, last_login_time=? WHERE id=?", ps -> {
            ps.setLong(1, now.toEpochMilli());
            ps.setLong(2, userId);
        });
    }

    @Override
    public boolean incrementRecoveryAttempts(long userId, int maxAttempts, Instant lockoutUntil, Instant now) {
        Optional<UserRecord> opt = findById(userId);
        if (opt.isEmpty()) return false;
        UserRecord u = opt.get();
        int attempts = u.recoveryAttempts() + 1;
        long lockout = attempts >= maxAttempts ? lockoutUntil.toEpochMilli() : 0;
        return update("UPDATE auth_users SET recovery_attempts=?, recovery_lockout_until=?, last_login_time=? WHERE id=?", ps -> {
            ps.setInt(1, attempts);
            ps.setLong(2, lockout);
            ps.setLong(3, now.toEpochMilli());
            ps.setLong(4, userId);
        });
    }

    @Override
    public boolean updateLastSessionTime(long userId, Instant now) {
        return update("UPDATE auth_users SET last_session_time=?, last_login_time=? WHERE id=?", ps -> {
            ps.setLong(1, now.toEpochMilli());
            ps.setLong(2, now.toEpochMilli());
            ps.setLong(3, userId);
        });
    }

    // ---- 2FA methods ----

    @Override
    public boolean setTotpSecret(long userId, String secret, Instant now) {
        return update("UPDATE auth_users SET totp_secret=?, last_login_time=? WHERE id=?", ps -> {
            ps.setString(1, secret);
            ps.setLong(2, now.toEpochMilli());
            ps.setLong(3, userId);
        });
    }

    @Override
    public boolean setBackupCodes(long userId, String codesJson, Instant now) {
        return update("UPDATE auth_users SET backup_codes_json=?, last_login_time=? WHERE id=?", ps -> {
            ps.setString(1, codesJson);
            ps.setLong(2, now.toEpochMilli());
            ps.setLong(3, userId);
        });
    }

    @Override
    public boolean setTwoFactorEnabled(long userId, boolean enabled, Instant now) {
        return update("UPDATE auth_users SET two_factor_enabled=?, last_login_time=? WHERE id=?", ps -> {
            ps.setInt(1, enabled ? 1 : 0);
            ps.setLong(2, now.toEpochMilli());
            ps.setLong(3, userId);
        });
    }

    @Override
    public boolean updateLastTwoFactorSuccess(long userId, Instant now) {
        return update("UPDATE auth_users SET last_two_factor_success=?, last_login_time=? WHERE id=?", ps -> {
            ps.setLong(1, now.toEpochMilli());
            ps.setLong(2, now.toEpochMilli());
            ps.setLong(3, userId);
        });
    }

    @Override
    public boolean resetTwoFactorAttempts(long userId, Instant now) {
        return update("UPDATE auth_users SET two_factor_attempts=0, two_factor_lockout_until=0, last_login_time=? WHERE id=?", ps -> {
            ps.setLong(1, now.toEpochMilli());
            ps.setLong(2, userId);
        });
    }

    @Override
    public boolean incrementTwoFactorAttempts(long userId, int maxAttempts, Instant lockoutUntil, Instant now) {
        Optional<UserRecord> opt = findById(userId);
        if (opt.isEmpty()) return false;
        UserRecord u = opt.get();
        int attempts = u.twoFactorAttempts() + 1;
        long lockout = attempts >= maxAttempts ? lockoutUntil.toEpochMilli() : 0;
        return update("UPDATE auth_users SET two_factor_attempts=?, two_factor_lockout_until=?, last_login_time=? WHERE id=?", ps -> {
            ps.setInt(1, attempts);
            ps.setLong(2, lockout);
            ps.setLong(3, now.toEpochMilli());
            ps.setLong(4, userId);
        });
    }

    @Override
    public boolean setTwoFactorRequired(long userId, boolean required, Instant now) {
        return update("UPDATE auth_users SET two_factor_required=?, last_login_time=? WHERE id=?", ps -> {
            ps.setInt(1, required ? 1 : 0);
            ps.setLong(2, now.toEpochMilli());
            ps.setLong(3, userId);
        });
    }

    @Override
    public boolean updateLast2faVerifiedIp(long userId, String ip, Instant now) {
        return update("UPDATE auth_users SET last_2fa_verified_ip=?, last_login_time=? WHERE id=?", ps -> {
            ps.setString(1, ip);
            ps.setLong(2, now.toEpochMilli());
            ps.setLong(3, userId);
        });
    }

    @Override
    public boolean updateLastLogoutLocation(long userId, String location, Instant now) {
        try {
            return update("UPDATE auth_users SET last_logout_location=?, last_login_time=? WHERE id=?", ps -> {
                ps.setString(1, location);
                ps.setLong(2, now.toEpochMilli());
                ps.setLong(3, userId);
            });
        } catch (Exception ignored) {
            // Column may not exist yet if migration is pending; safe to skip
            return false;
        }
    }

    @Override
    public boolean deleteUser(long userId) {
        return update("DELETE FROM auth_users WHERE id=?", ps -> {
            ps.setLong(1, userId);
        });
    }

    // ---- UUID + fingerprint methods (V5) ----

    @Override
    public boolean updateUuid(long userId, String uuid) {
        return update("UPDATE auth_users SET uuid=? WHERE id=?", ps -> {
            ps.setString(1, uuid);
            ps.setLong(2, userId);
        });
    }

    @Override
    public boolean updateClientFingerprint(long userId, String clientBrand, String clientSettingsHash, String fingerprint) {
        return update("UPDATE auth_users SET client_brand=?, client_settings_hash=?, last_client_fingerprint=? WHERE id=?", ps -> {
            ps.setString(1, clientBrand);
            ps.setString(2, clientSettingsHash);
            ps.setString(3, fingerprint);
            ps.setLong(4, userId);
        });
    }

    // ---- internal helpers ----

    private Optional<UserRecord> findById(long userId) {
        String sql = "SELECT * FROM auth_users WHERE id=?";
        try (Connection c = ds.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setLong(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return Optional.empty();
                return Optional.of(map(rs));
            }
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    private UserRecord map(ResultSet rs) throws SQLException {
        long id = rs.getLong("id");
        String usernameLower = rs.getString("username_lower");
        String usernameOrig = rs.getString("username_original");
        String pwHash = rs.getString("password_hash");
        Instant reg = Instant.ofEpochMilli(rs.getLong("registration_time"));
        Instant lastLogin = Instant.ofEpochMilli(rs.getLong("last_login_time"));
        String lastIp = rs.getString("last_ip");
        boolean autologin = rs.getInt("autologin_enabled") == 1;
        String ip1 = rs.getString("trusted_ip_1");
        long s1 = rs.getLong("trusted_ip_1_score");
        String ip2 = rs.getString("trusted_ip_2");
        long s2 = rs.getLong("trusted_ip_2_score");
        String rq = rs.getString("recovery_question");
        String rah = rs.getString("recovery_answer_hash");
        int loginAttempts = rs.getInt("login_attempts");
        Instant loginLockoutUntil = Instant.ofEpochMilli(rs.getLong("login_lockout_until"));
        int recoveryAttempts = rs.getInt("recovery_attempts");
        Instant recoveryLockoutUntil = Instant.ofEpochMilli(rs.getLong("recovery_lockout_until"));
        Instant lastSessionTime = Instant.ofEpochMilli(rs.getLong("last_session_time"));

        // 2FA fields
        boolean twoFactorEnabled = rs.getInt("two_factor_enabled") == 1;
        String totpSecret = rs.getString("totp_secret");
        String backupCodesJson = rs.getString("backup_codes_json");
        Instant lastTwoFactorSuccess = Instant.ofEpochMilli(rs.getLong("last_two_factor_success"));
        int twoFactorAttempts = rs.getInt("two_factor_attempts");
        Instant twoFactorLockoutUntil = Instant.ofEpochMilli(rs.getLong("two_factor_lockout_until"));
        boolean twoFactorRequired = rs.getInt("two_factor_required") == 1;
        String last2faVerifiedIp = rs.getString("last_2fa_verified_ip");

        // Last logout location
        String lastLogoutLocation = null;
        try { lastLogoutLocation = rs.getString("last_logout_location"); } catch (SQLException ignored) {}

        // UUID + client fingerprint (V5)
        String uuid = null;
        String clientBrand = null;
        String clientSettingsHash = null;
        String lastClientFingerprint = null;
        try { uuid = rs.getString("uuid"); } catch (SQLException ignored) {}
        try { clientBrand = rs.getString("client_brand"); } catch (SQLException ignored) {}
        try { clientSettingsHash = rs.getString("client_settings_hash"); } catch (SQLException ignored) {}
        try { lastClientFingerprint = rs.getString("last_client_fingerprint"); } catch (SQLException ignored) {}

        return new UserRecord(id, usernameLower, usernameOrig, pwHash,
                reg, lastLogin, lastIp, autologin,
                ip1, s1, ip2, s2,
                rq, rah,
                loginAttempts, loginLockoutUntil,
                recoveryAttempts, recoveryLockoutUntil,
                lastSessionTime,
                twoFactorEnabled, totpSecret, backupCodesJson,
                lastTwoFactorSuccess, twoFactorAttempts, twoFactorLockoutUntil,
                twoFactorRequired, last2faVerifiedIp, lastLogoutLocation,
                uuid, clientBrand, clientSettingsHash, lastClientFingerprint);
    }

    private boolean update(String sql, StatementFiller filler) {
        try (Connection c = ds.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            filler.fill(ps);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    @FunctionalInterface
    private interface StatementFiller {
        void fill(PreparedStatement ps) throws SQLException;
    }
}

