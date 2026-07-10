package pt.henrique.serverauth.security;

import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import pt.henrique.serverauth.config.PluginConfig;
import pt.henrique.serverauth.i18n.MessageService;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Centralised security event logger. Writes all security-relevant events
 * to a configurable log file and, where configured, notifies online OPs.
 *
 * <p>Thread-safe — all file writes are synchronized on a single lock object.</p>
 */
public final class SecurityLogger {

    private static final DateTimeFormatter FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final PluginConfig cfg;
    private final MessageService msg;
    private final Logger logger;
    private final Path logFile;
    private final Object writeLock = new Object();

    public SecurityLogger(PluginConfig cfg, MessageService msg, Logger logger, File dataFolder) {
        this.cfg = cfg;
        this.msg = msg;
        this.logger = logger;
        this.logFile = dataFolder.toPath().resolve(cfg.security().loginLogFile());
    }

    // ──────────────────── Event methods ────────────────────

    /** Successful manual /login */
    public void logLoginSuccess(String playerName, String ip) {
        write("LOGIN_SUCCESS", playerName, "ip=" + ip);
    }

    /** Failed /login (wrong password) */
    public void logLoginFailure(String playerName, String ip) {
        write("LOGIN_FAILURE", playerName, "ip=" + ip);
        notifyOpsOnFailedLogin(playerName, ip);
    }

    /** Successful /register */
    public void logRegistration(String playerName, String ip) {
        write("REGISTER", playerName, "ip=" + ip);
    }

    /** Auto-login accepted (4-layer check passed) */
    public void logAutoLogin(String playerName, String ip) {
        write("AUTO_LOGIN", playerName, "ip=" + ip);
    }

    /** Grace period login */
    public void logGraceLogin(String playerName, String ip) {
        write("GRACE_LOGIN", playerName, "ip=" + ip);
    }

    /** Auto-login denied (fingerprint / config mismatch) */
    public void logAutoLoginDenied(String playerName, String ip, String reason) {
        write("AUTO_LOGIN_DENIED", playerName, "ip=" + ip + " reason=" + reason);
    }

    /** 2FA verification succeeded */
    public void log2FASuccess(String playerName, String ip) {
        write("2FA_SUCCESS", playerName, "ip=" + ip);
    }

    /** 2FA verification failed */
    public void log2FAFailure(String playerName, String ip) {
        write("2FA_FAILURE", playerName, "ip=" + ip);
    }

    /** UUID mismatch detected on join */
    public void logUuidMismatch(String playerName, String expected, String actual, String ip) {
        write("UUID_MISMATCH", playerName,
                "expected=" + expected + " actual=" + actual + " ip=" + ip);
    }

    /** In-memory session dropped because reconnect IP differs from session IP */
    public void logSessionIpMismatch(String playerName, String currentIp) {
        write("SESSION_IP_MISMATCH", playerName, "now_ip=" + currentIp);
    }

    /** Fingerprint mismatch detected during auto-login */
    public void logFingerprintMismatch(String playerName, String stored, String current) {
        write("FINGERPRINT_MISMATCH", playerName,
                "stored=" + stored + " current=" + current);
    }

    /** Password changed (by self or admin) */
    public void logPasswordChange(String playerName, String changedBy) {
        write("PASSWORD_CHANGE", playerName, "changedBy=" + changedBy);
    }

    /** Account recovery initiated */
    public void logAccountRecovery(String playerName, String ip) {
        write("ACCOUNT_RECOVERY", playerName, "ip=" + ip);
    }

    /** Admin action (setpassword, delete, reset2fa) */
    public void logAdminAction(String adminName, String action, String targetPlayer) {
        write("ADMIN_" + action.toUpperCase(), targetPlayer, "admin=" + adminName);
        notifyOpsOnAdminAction(adminName, action, targetPlayer);
    }

    /** Player logout */
    public void logLogout(String playerName) {
        write("LOGOUT", playerName, "");
    }

    /** 2FA state change (enabled / disabled) */
    public void log2FAStateChange(String playerName, boolean enabled) {
        write(enabled ? "2FA_ENABLED" : "2FA_DISABLED", playerName, "");
    }

    /** Player kicked after max login attempts */
    public void logMaxAttemptsKick(String playerName, String ip) {
        write("MAX_ATTEMPTS_KICK", playerName, "ip=" + ip);
    }

    // ──────────────────── OP notifications ────────────────────

    private void notifyOpsOnFailedLogin(String playerName, String ip) {
        if (!cfg.security().notifyOpsOnFailedLogin()) return;
        for (Player op : Bukkit.getOnlinePlayers()) {
            if (op.isOp()) {
                msg.send(op, "security.login-failure-warning", Map.of(
                        "player", playerName,
                        "ip", ip
                ));
            }
        }
    }

    /** Notify OPs when UUID mismatch is detected (called externally from AuthService). */
    public void notifyOpsUuidMismatch(String playerName, String expected, String actual, String ip) {
        if (!cfg.security().notifyOpsOnUuidMismatch()) return;
        for (Player op : Bukkit.getOnlinePlayers()) {
            if (op.isOp()) {
                msg.send(op, "security.uuid-mismatch-warning", Map.of(
                        "player", playerName,
                        "expected", expected,
                        "actual", actual,
                        "ip", ip
                ));
            }
        }
    }

    private void notifyOpsOnAdminAction(String adminName, String action, String targetPlayer) {
        for (Player op : Bukkit.getOnlinePlayers()) {
            if (op.isOp()) {
                msg.send(op, "security.admin-action", Map.of(
                        "admin", adminName,
                        "action", action,
                        "player", targetPlayer
                ));
            }
        }
    }

    // ──────────────────── File writing ────────────────────

    private void write(String event, String player, String details) {
        if (!cfg.security().logLoginAttempts()) return;
        String timestamp = LocalDateTime.now().format(FMT);
        // Sanitize control chars (newlines etc.) so client-controlled values
        // (Bedrock names, client brand fingerprint, ...) cannot forge log lines.
        String line = String.format("[%s] %s player=%s %s%n", timestamp, event, sanitize(player),
                details == null ? "" : sanitize(details.trim()));

        writeLine(line);
    }

    /** Replace control characters with spaces to keep each log entry on a single line. */
    private static String sanitize(String s) {
        return s == null ? "" : s.replaceAll("\\p{Cntrl}", " ");
    }

    private void writeLine(String line) {
        synchronized (writeLock) {
            try {
                Files.createDirectories(logFile.getParent());
                Files.writeString(logFile, line,
                        StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE,
                        StandardOpenOption.APPEND);
            } catch (IOException e) {
                logger.warning("[SecurityLogger] Failed to write to " + logFile + ": " + e.getMessage());
            }
        }
    }
}

