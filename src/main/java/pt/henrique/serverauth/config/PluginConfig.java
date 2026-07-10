package pt.henrique.serverauth.config;

import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.FileConfiguration;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public record PluginConfig(
        String language,
        boolean overrideHelpCommand,
        PasswordConfig password,
        int reconnectGraceSeconds,
        SecurityConfig security,
        LockdownConfig lockdown,
        StorageConfig storage,
        int titleReminderIntervalSeconds,
        boolean remindRecoveryOnJoin,
        TwoFactorConfig twoFactor,
        PolicyConfig policy,
        WebConfig web,
        AutoLoginConfig autoLogin,
        FingerprintConfig fingerprint,
        FloodgateConfig floodgate
) {

    public static PluginConfig load(FileConfiguration cfg) {
        String language = cfg.getString("language", "en_US");
        boolean overrideHelp = cfg.getBoolean("override-help-command", false);

        ConfigurationSection pw = cfg.getConfigurationSection("password");
        int minLen = pw != null ? pw.getInt("min-length", 6) : 6;
        boolean requireMatch = pw == null || pw.getBoolean("require-confirm-match", true);

        int grace = Math.max(0, cfg.getInt("reconnect-grace-seconds", 60));

        SecurityConfig security = SecurityConfig.from(cfg.getConfigurationSection("security"));
        LockdownConfig lockdown = LockdownConfig.from(cfg.getConfigurationSection("lockdown"), overrideHelp);
        StorageConfig storage = StorageConfig.from(cfg.getConfigurationSection("storage"));

        int titleInterval = Math.max(0, cfg.getInt("title-reminder-interval-seconds", 5));
        boolean remindRecovery = cfg.getBoolean("remind-recovery-on-join", false);

        TwoFactorConfig twoFactor = TwoFactorConfig.from(cfg.getConfigurationSection("two-factor"));
        PolicyConfig policy = PolicyConfig.from(cfg.getConfigurationSection("policy"));
        WebConfig web = WebConfig.from(cfg.getConfigurationSection("web-server"));
        AutoLoginConfig autoLogin = AutoLoginConfig.from(cfg.getConfigurationSection("autologin"));
        FingerprintConfig fingerprint = FingerprintConfig.from(cfg.getConfigurationSection("fingerprint"));
        FloodgateConfig floodgate = FloodgateConfig.from(cfg.getConfigurationSection("floodgate"));

        return new PluginConfig(
                language,
                overrideHelp,
                new PasswordConfig(Math.max(1, minLen), requireMatch),
                grace,
                security,
                lockdown,
                storage,
                titleInterval,
                remindRecovery,
                twoFactor,
                policy,
                web,
                autoLogin,
                fingerprint,
                floodgate
        );
    }

    public String language() {
        return language == null ? "en_US" : language;
    }

    /** Bedrock (Floodgate) auto-login: Floodgate already verifies the player's
     *  Xbox Live identity before they reach the server, so we trust it and skip
     *  register/login/2FA entirely for those players. */
    public record FloodgateConfig(boolean autoLogin) {
        static FloodgateConfig from(ConfigurationSection sec) {
            boolean autoLogin = sec == null || sec.getBoolean("auto-login", true);
            return new FloodgateConfig(autoLogin);
        }
    }

    public record PasswordConfig(int minLength, boolean requireConfirmMatch) {
    }

    public record SecurityConfig(int maxLoginAttempts, int loginLockoutSeconds,
                                 int maxRecoveryAttempts, int recoveryLockoutSeconds,
                                 int sessionExpiryHours, int bcryptCost,
                                 boolean kickOnMaxAttempts,
                                 boolean logLoginAttempts, String loginLogFile,
                                 boolean notifyOpsOnFailedLogin,
                                 boolean notifyOpsOnUuidMismatch,
                                 boolean sessionRequireIpMatchOnRejoin) {

        static SecurityConfig from(ConfigurationSection sec) {
            int maxLogin = sec != null ? sec.getInt("max-login-attempts", 5) : 5;
            int loginLockout = sec != null ? sec.getInt("login-lockout-seconds", 300) : 300;
            int maxRecovery = sec != null ? sec.getInt("max-recovery-attempts", 5) : 5;
            int recoveryLockout = sec != null ? sec.getInt("recovery-lockout-seconds", 300) : 300;
            int expiry = sec != null ? sec.getInt("session-expiry-hours", 0) : 0;
            int cost = sec != null ? sec.getInt("bcrypt-cost", 12) : 12;
            boolean kickOnMax = sec != null && sec.getBoolean("kick-on-max-attempts", false);
            boolean logAttempts = sec == null || sec.getBoolean("log-login-attempts", true);
            String logFile = sec != null ? sec.getString("login-log-file", "auth-log.txt") : "auth-log.txt";
            boolean notifyFailed = sec != null && sec.getBoolean("notify-ops-on-failed-login", false);
            boolean notifyUuid = sec == null || sec.getBoolean("notify-ops-on-uuid-mismatch", true);
            // Default ON: if a player reconnects from a different IP than the one tied to the
            // current in-memory session, the session is dropped and /login is required again.
            // Catches the "left for hours from home wifi, returned on 5G" case where the old
            // behaviour (session lives forever within a JVM run) would skip auth.
            boolean sessionIpRejoin = sec == null || sec.getBoolean("session-require-ip-match-on-rejoin", true);

            // keep BCrypt cost sane
            cost = Math.min(16, Math.max(10, cost));

            return new SecurityConfig(
                    Math.max(1, maxLogin),
                    Math.max(1, loginLockout),
                    Math.max(1, maxRecovery),
                    Math.max(1, recoveryLockout),
                    Math.max(0, expiry),
                    cost,
                    kickOnMax,
                    logAttempts, logFile,
                    notifyFailed,
                    notifyUuid,
                    sessionIpRejoin
            );
        }
    }

    public record LockdownConfig(boolean enabled,
                                boolean applyDarkness,
                                boolean teleportToAuthSpawn,
                                String spawnLocation,
                                boolean hideCoordinatesDuringLogin,
                                String loginSpawnLocation,
                                List<String> allowedCommands) {

        static LockdownConfig from(ConfigurationSection lock, boolean overrideHelp) {
            boolean enabled = lock == null || lock.getBoolean("enabled", true);
            boolean darkness = lock == null || lock.getBoolean("apply-darkness", true);
            boolean tp = lock != null && lock.getBoolean("teleport-to-auth-spawn", false);
            String spawn = lock != null ? lock.getString("spawn-location", "world,0.5,100,0.5,0,0") : "world,0.5,100,0.5,0,0";
            boolean hideCoordinates = lock == null || lock.getBoolean("hide-coordinates-during-login", true);
            String loginSpawn = lock != null ? lock.getString("login-spawn-location", "world,0,0,0,0,0") : "world,0,0,0,0,0";

            List<String> allowed = new ArrayList<>();
            if (lock != null) {
                allowed.addAll(lock.getStringList("allowed-commands"));
            }

            if (allowed.isEmpty()) {
                allowed.add("/register");
                allowed.add("/login");
                allowed.add("/authhelp");
                if (overrideHelp) allowed.add("/help");
                allowed.add("/autologin");
                allowed.add("/changepassword");
                allowed.add("/logout");
                allowed.add("/recover");
                allowed.add("/recovery");
                allowed.add("/2fa");
            }

            return new LockdownConfig(enabled, darkness, tp, spawn, hideCoordinates, loginSpawn, allowed);
        }

        public List<String> allowedNormalized() {
            List<String> out = new ArrayList<>(allowedCommands.size());
            for (String cmd : allowedCommands) {
                if (cmd == null) continue;
                String s = cmd.trim().toLowerCase(Locale.ROOT);
                if (s.startsWith("/")) s = s.substring(1);
                if (!s.isBlank()) out.add(s);
            }
            return out;
        }
    }

    public record TwoFactorConfig(boolean enabled, int backupCodeCount,
                                   int maxVerifyAttempts, int verifyLockoutSeconds,
                                   int setupTokenExpiryMinutes,
                                   boolean requireOnlyOnIpChange,
                                   boolean sameIpRandomChallengeEnabled,
                                   int sameIpRandomChallengeOneInN,
                                   int maxTrustedSessionHours,
                                   boolean debugSkipMessages) {
        static TwoFactorConfig from(ConfigurationSection sec) {
            boolean enabled = sec != null && sec.getBoolean("enabled", true);
            int backupCodes = sec != null ? sec.getInt("backup-code-count", 8) : 8;
            int maxAttempts = sec != null ? sec.getInt("max-verify-attempts", 5) : 5;
            int lockout = sec != null ? sec.getInt("verify-lockout-seconds", 300) : 300;
            int tokenExpiry = sec != null ? sec.getInt("setup-token-expiry-minutes", 15) : 15;

            boolean requireOnlyOnIpChange = sec != null && sec.getBoolean("require-only-on-ip-change", false);

            ConfigurationSection randomSec = sec != null ? sec.getConfigurationSection("same-ip-random-challenge") : null;
            boolean randomEnabled = randomSec != null && randomSec.getBoolean("enabled", false);
            int oneInN = randomSec != null ? randomSec.getInt("one-in-n", 10) : 10;

            int maxTrusted = sec != null ? sec.getInt("max-trusted-session-hours", 0) : 0;
            boolean debug = sec != null && sec.getBoolean("debug-skip-messages", false);

            return new TwoFactorConfig(
                    enabled,
                    Math.max(1, backupCodes),
                    Math.max(1, maxAttempts),
                    Math.max(1, lockout),
                    Math.max(1, tokenExpiry),
                    requireOnlyOnIpChange,
                    randomEnabled,
                    Math.max(2, oneInN),
                    Math.max(0, maxTrusted),
                    debug
            );
        }
    }

    public record PolicyConfig(boolean opsRequire2FA, boolean adminsRequire2FA,
                                int maxAccountsPerIp, boolean blockRegistrationInMaintenance,
                                int inactivityTimeoutMinutes) {
        static PolicyConfig from(ConfigurationSection sec) {
            boolean ops = sec != null && sec.getBoolean("require-2fa-for-ops", true);
            boolean admins = sec != null && sec.getBoolean("require-2fa-for-admins", true);
            int maxPerIp = sec != null ? sec.getInt("max-accounts-per-ip", 0) : 0;
            boolean blockReg = sec != null && sec.getBoolean("block-registration-in-maintenance", false);
            int inactivity = sec != null ? sec.getInt("inactivity-timeout-minutes", 0) : 0;
            return new PolicyConfig(ops, admins, Math.max(0, maxPerIp), blockReg, Math.max(0, inactivity));
        }
    }

    public record WebConfig(boolean enabled, int port, String host, String publicUrl) {
        static WebConfig from(ConfigurationSection sec) {
            boolean enabled = sec != null && sec.getBoolean("enabled", true);
            int port = sec != null ? sec.getInt("port", 8921) : 8921;
            String host = sec != null ? sec.getString("host", "127.0.0.1") : "127.0.0.1";
            String publicUrl = sec != null ? sec.getString("public-url", "http://localhost:" + port) : "http://localhost:" + port;
            return new WebConfig(enabled, Math.max(1, port), host, publicUrl);
        }
    }

    public record AutoLoginConfig(boolean requireUuidMatch, boolean requireIpMatch,
                                    boolean requireFingerprintMatch, boolean debugAutologin,
                                    int delayTicks, boolean logUuidMismatchWarning,
                                    boolean logFingerprintMismatch) {
        static AutoLoginConfig from(ConfigurationSection sec) {
            boolean uuid = sec == null || sec.getBoolean("require-uuid-match", true);
            boolean ip = sec == null || sec.getBoolean("require-ip-match", true);
            boolean fp = sec == null || sec.getBoolean("require-fingerprint-match", true);
            boolean debug = sec != null && sec.getBoolean("debug-autologin", false);
            int delay = sec != null ? sec.getInt("delay-ticks", 10) : 10;
            boolean logUuid = sec == null || sec.getBoolean("log-uuid-mismatch-warning", true);
            boolean logFp = sec == null || sec.getBoolean("log-fingerprint-mismatch", true);
            return new AutoLoginConfig(uuid, ip, fp, debug, Math.max(1, delay), logUuid, logFp);
        }
    }

    public record FingerprintConfig(boolean captureBrand, boolean captureSettings,
                                     boolean enforceBrand, boolean enforceSettings) {
        static FingerprintConfig from(ConfigurationSection sec) {
            boolean brand = sec == null || sec.getBoolean("capture-brand", true);
            boolean settings = sec == null || sec.getBoolean("capture-settings", true);
            boolean enfBrand = sec == null || sec.getBoolean("enforce-brand", true);
            boolean enfSettings = sec != null && sec.getBoolean("enforce-settings", false);
            return new FingerprintConfig(brand, settings, enfBrand, enfSettings);
        }
    }

    public record StorageConfig(StorageType type, SqliteConfig sqlite, MysqlConfig mysql) {
        static StorageConfig from(ConfigurationSection stor) {
            String typeRaw = stor != null ? stor.getString("type", "sqlite") : "sqlite";
            StorageType type = "mysql".equalsIgnoreCase(typeRaw) ? StorageType.MYSQL : StorageType.SQLITE;

            ConfigurationSection sq = stor != null ? stor.getConfigurationSection("sqlite") : null;
            ConfigurationSection my = stor != null ? stor.getConfigurationSection("mysql") : null;

            SqliteConfig sqlite = new SqliteConfig(sq != null ? sq.getString("file", "auth.db") : "auth.db");
            MysqlConfig mysql = new MysqlConfig(
                    my != null ? my.getString("host", "localhost") : "localhost",
                    my != null ? my.getInt("port", 3306) : 3306,
                    my != null ? my.getString("database", "minecraft") : "minecraft",
                    my != null ? my.getString("username", "root") : "root",
                    my != null ? my.getString("password", "") : "",
                    my != null && my.getBoolean("use-ssl", false)
            );

            return new StorageConfig(type, sqlite, mysql);
        }
    }

    public enum StorageType { SQLITE, MYSQL }

    public record SqliteConfig(String file) {}

    public record MysqlConfig(String host, int port, String database, String username, String password, boolean useSsl) {}
}
