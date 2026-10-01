package pt.henrique.serverauth.auth;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;
import pt.henrique.serverauth.api.events.*;
import pt.henrique.serverauth.config.PluginConfig;
import pt.henrique.serverauth.i18n.MessageService;
import pt.henrique.serverauth.security.PasswordHasher;
import pt.henrique.serverauth.security.SecurityLogger;
import pt.henrique.serverauth.storage.UserRecord;
import pt.henrique.serverauth.storage.UserRepository;
import pt.henrique.serverauth.util.Async;
import pt.henrique.serverauth.util.IpUtil;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public final class TwoFactorService {

    private static final String ISSUER = "ServerAUTH";

    private final Plugin plugin;
    private final PluginConfig cfg;
    private final MessageService msg;
    private final Async async;
    private final UserRepository repo;
    private final PasswordHasher hasher;
    private final SessionService sessions;
    private final LockdownService lockdown;

    /** Late-initialized: client fingerprint capture service. */
    private ClientFingerprintService fingerprintService;

    /** Late-initialized: centralised security event logger. */
    private SecurityLogger securityLogger;

    private final GoogleAuthenticator gAuth;

    // Setup tokens: player UUID -> SetupToken
    private final ConcurrentHashMap<UUID, SetupToken> setupTokens = new ConcurrentHashMap<>();
    // Web setup tokens: random token string -> player UUID
    private final ConcurrentHashMap<String, UUID> webTokens = new ConcurrentHashMap<>();
    // Rate limiter for 2FA verify attempts
    private final ConcurrentHashMap<UUID, AttemptTracker> verifyAttempts = new ConcurrentHashMap<>();

    private final SecureRandom secureRandom = new SecureRandom();

    public TwoFactorService(Plugin plugin, PluginConfig cfg, MessageService msg, Async async,
                            UserRepository repo, PasswordHasher hasher, SessionService sessions, LockdownService lockdown) {
        this.plugin = plugin;
        this.cfg = cfg;
        this.msg = msg;
        this.async = async;
        this.repo = repo;
        this.hasher = hasher;
        this.sessions = sessions;
        this.lockdown = lockdown;

        GoogleAuthenticatorConfig gaConfig = new GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder()
                .setWindowSize(5) // ±2 time steps (~±60s) to tolerate minor server clock drift
                .build();
        this.gAuth = new GoogleAuthenticator(gaConfig);
    }

    /** Must be called after ClientFingerprintService is constructed. */
    public void setFingerprintService(ClientFingerprintService fingerprintService) {
        this.fingerprintService = fingerprintService;
    }

    /** Must be called after SecurityLogger is constructed. */
    public void setSecurityLogger(SecurityLogger securityLogger) {
        this.securityLogger = securityLogger;
    }

    /** Creates a setup token for the player. Returns the web token string for the URL. */
    public String createSetupToken(UUID uuid, String playerName) {
        GoogleAuthenticatorKey key = gAuth.createCredentials();
        String secret = key.getKey();

        // Invalidate any earlier link for this player. Without this the previous
        // token string stays in webTokens and resolves to the new setup session,
        // so an older link that leaked (pasted in chat, browser history, a proxy
        // log) would still enrol an authenticator against the new secret.
        SetupToken previous = setupTokens.remove(uuid);
        if (previous != null) {
            webTokens.remove(previous.webToken());
        }

        // Generate random web token
        String webToken = generateRandomToken();

        long expiresAt = System.currentTimeMillis() + (cfg.twoFactor().setupTokenExpiryMinutes() * 60_000L);

        // Generate backup codes
        List<String> backupCodesPlain = generateBackupCodes(cfg.twoFactor().backupCodeCount());

        SetupToken token = new SetupToken(secret, webToken, expiresAt, playerName, backupCodesPlain);
        setupTokens.put(uuid, token);
        webTokens.put(webToken, uuid);

        return webToken;
    }

    /** Get setup token info for a player (used by web server). */
    public SetupToken getSetupToken(UUID uuid) {
        SetupToken t = setupTokens.get(uuid);
        if (t == null) return null;
        if (System.currentTimeMillis() > t.expiresAt()) {
            setupTokens.remove(uuid);
            webTokens.remove(t.webToken());
            return null;
        }
        return t;
    }

    /** Resolve a web token to a player UUID. */
    public UUID resolveWebToken(String webToken) {
        UUID uuid = webTokens.get(webToken);
        if (uuid == null) return null;
        SetupToken t = setupTokens.get(uuid);
        if (t == null || System.currentTimeMillis() > t.expiresAt()) {
            webTokens.remove(webToken);
            if (t != null) setupTokens.remove(uuid);
            return null;
        }
        return uuid;
    }

    /** Build the otpauth URI for QR codes. */
    public String buildOtpAuthUri(String secret, String playerName) {
        return "otpauth://totp/" + ISSUER + ":" + urlEncode(playerName)
                + "?secret=" + secret + "&issuer=" + ISSUER;
    }

    /** Verify a raw TOTP code against a secret. Usable by other services (e.g., recovery). */
    public boolean verifyTotpCode(String secret, int code) {
        return gAuth.authorize(secret, code);
    }

    /** Outcome of a browser-based 2FA confirmation, so the web page can show a precise message. */
    public enum WebSetupResult { SUCCESS, EXPIRED, WRONG_CODE, ERROR }

    /**
     * Confirm 2FA setup from the browser. Validates the TOTP code, persists to DB,
     * and notifies the in-game player. Called from the web server thread — does NOT
     * require a Player object.
     *
     * <p>Returns a {@link WebSetupResult} so the page can distinguish "wrong code" from
     * "expired session" or "server error" instead of always showing "invalid code".
     */
    public WebSetupResult confirmSetupFromWeb(UUID uuid, int code) {
        SetupToken token = getSetupToken(uuid);
        if (token == null) return WebSetupResult.EXPIRED;

        if (!gAuth.authorize(token.secret(), code)) return WebSetupResult.WRONG_CODE;

        // Persist
        String playerName = token.playerName();
        String lower = playerName.toLowerCase(Locale.ROOT);
        List<String> hashedCodes = token.backupCodesPlain().stream().map(hasher::hash).toList();
        String codesJson = toJson(hashedCodes);

        // Run DB writes synchronously (we're on the web server thread, not the main thread)
        try {
            Optional<UserRecord> opt = repo.findByUsernameLower(lower);
            if (opt.isEmpty()) {
                plugin.getLogger().warning("[2FA] Setup confirm failed: no account found for " + playerName);
                return WebSetupResult.ERROR;
            }
            long id = opt.get().id();
            Instant now = Instant.now();
            repo.setTotpSecret(id, token.secret(), now);
            repo.setBackupCodes(id, codesJson, now);
            repo.setTwoFactorEnabled(id, true, now);
        } catch (Exception e) {
            plugin.getLogger().warning("[2FA] Failed to persist 2FA setup for " + playerName + ": " + e.getMessage());
            return WebSetupResult.ERROR;
        }

        // Clean up tokens
        setupTokens.remove(uuid);
        webTokens.remove(token.webToken());

        // Notify the in-game player (on the main thread)
        async.sync(() -> {
            Player p = Bukkit.getPlayer(uuid);
            if (p != null && p.isOnline()) {
                msg.send(p, "2fa.confirm-success");
                if (securityLogger != null) securityLogger.log2FAStateChange(p.getName(), true);
                Bukkit.getPluginManager().callEvent(new Player2FAStateChangeEvent(p, true));
            }
        });

        return WebSetupResult.SUCCESS;
    }

    /**
     * Confirm 2FA setup from in-game (CLI fallback when web server is disabled).
     */
    public void confirmSetupCli(Player p, int code) {
        UUID uuid = p.getUniqueId();
        SetupToken token = getSetupToken(uuid);
        if (token == null) {
            msg.send(p, "2fa.setup-expired");
            return;
        }

        if (!gAuth.authorize(token.secret(), code)) {
            msg.send(p, "2fa.confirm-fail");
            return;
        }

        String lower = p.getName().toLowerCase(Locale.ROOT);
        List<String> hashedCodes = token.backupCodesPlain().stream().map(hasher::hash).toList();
        String codesJson = toJson(hashedCodes);

        async.run(() -> {
            Optional<UserRecord> opt = repo.findByUsernameLower(lower);
            if (opt.isEmpty()) return;
            long id = opt.get().id();
            Instant now = Instant.now();
            repo.setTotpSecret(id, token.secret(), now);
            repo.setBackupCodes(id, codesJson, now);
            repo.setTwoFactorEnabled(id, true, now);
        }).thenRun(() -> async.sync(() -> {
            setupTokens.remove(uuid);
            webTokens.remove(token.webToken());

            msg.send(p, "2fa.confirm-success");
            msg.send(p, "2fa.backup-codes-header");
            for (String code1 : token.backupCodesPlain()) {
                p.sendMessage("  §e" + code1);
            }
            msg.send(p, "2fa.backup-codes-footer");

            if (securityLogger != null) securityLogger.log2FAStateChange(p.getName(), true);
            Bukkit.getPluginManager().callEvent(new Player2FAStateChangeEvent(p, true));
        }));
    }

    /** Verify a 2FA code during login (pending state). Handles both TOTP and backup codes. */
    public void verify(Player p, String codeInput) {
        UUID uuid = p.getUniqueId();

        // Rate limiting
        AttemptTracker tracker = verifyAttempts.computeIfAbsent(uuid, k -> new AttemptTracker());
        Instant now = Instant.now();
        if (tracker.lockoutUntil != null && tracker.lockoutUntil.isAfter(now)) {
            long seconds = Math.max(1, (tracker.lockoutUntil.toEpochMilli() - now.toEpochMilli()) / 1000);
            msg.send(p, "2fa.lockout", Map.of("seconds", String.valueOf(seconds)));
            return;
        }

        String lower = p.getName().toLowerCase(Locale.ROOT);
        async.supply(() -> repo.findByUsernameLower(lower)).thenAccept(opt -> {
            if (opt.isEmpty()) return;
            UserRecord u = opt.get();

            if (!u.has2FA()) {
                async.sync(() -> msg.send(p, "2fa.not-enabled"));
                return;
            }

            // Check DB-level lockout
            if (u.twoFactorLockoutUntil().isAfter(now)) {
                long seconds = Math.max(1, (u.twoFactorLockoutUntil().toEpochMilli() - now.toEpochMilli()) / 1000);
                async.sync(() -> msg.send(p, "2fa.lockout", Map.of("seconds", String.valueOf(seconds))));
                return;
            }

            // Try TOTP code first
            boolean success = false;
            boolean backupUsed = false;
            try {
                int numericCode = Integer.parseInt(codeInput.trim());
                success = gAuth.authorize(u.totpSecret(), numericCode);
            } catch (NumberFormatException ignored) {
                // Not a numeric code, try backup
            }

            // Try backup code if TOTP failed
            if (!success && u.backupCodesJson() != null) {
                String matchResult = checkAndRemoveBackupCode(codeInput.trim(), u.backupCodesJson());
                if (matchResult != null) {
                    success = true;
                    backupUsed = true;
                    // Update backup codes (remove used one)
                    repo.setBackupCodes(u.id(), matchResult, now);
                }
            }

            if (!success) {
                // Increment attempts
                tracker.attempts++;
                if (tracker.attempts >= cfg.twoFactor().maxVerifyAttempts()) {
                    tracker.lockoutUntil = now.plusSeconds(cfg.twoFactor().verifyLockoutSeconds());
                    Instant lockout = now.plusSeconds(cfg.twoFactor().verifyLockoutSeconds());
                    repo.incrementTwoFactorAttempts(u.id(), cfg.twoFactor().maxVerifyAttempts(), lockout, now);
                }
                String failIp = IpUtil.ipString(p.getAddress() != null ? p.getAddress().getAddress() : null);
                if (securityLogger != null) securityLogger.log2FAFailure(p.getName(), failIp);
                async.sync(() -> msg.send(p, "2fa.verify-fail"));
                return;
            }

            // Success!
            tracker.attempts = 0;
            tracker.lockoutUntil = null;
            String ip = IpUtil.ipString(p.getAddress() != null ? p.getAddress().getAddress() : null);
            repo.resetTwoFactorAttempts(u.id(), now);
            repo.updateLastTwoFactorSuccess(u.id(), now);
            repo.updateLast2faVerifiedIp(u.id(), ip, now);
            if (securityLogger != null) securityLogger.log2FASuccess(p.getName(), ip);

            // Update client fingerprint after successful 2FA
            if (fingerprintService != null) {
                String fp = fingerprintService.getFingerprint(uuid);
                String brand = fingerprintService.getBrand(uuid);
                String settingsHash = fingerprintService.getSettingsHash(uuid);
                repo.updateClientFingerprint(u.id(), brand, settingsHash, fp);
            }

            boolean wasBackup = backupUsed;
            async.sync(() -> {
                sessions.clearTwofaPending(uuid);
                sessions.markLoggedIn(uuid, ip, now);

                if (wasBackup) {
                    msg.send(p, "2fa.verify-backup-used");
                } else {
                    msg.send(p, "2fa.verify-success");
                }

                // Restore player to their real location after successful 2FA
                lockdown.restoreAndUntrack(p);

                Bukkit.getPluginManager().callEvent(new Player2FASuccessEvent(p));
                Bukkit.getPluginManager().callEvent(new PlayerFullyAuthenticatedEvent(p));
            });
        });
    }

    /** Disable 2FA. Requires valid TOTP code. */
    public void disable(Player p, String codeInput) {
        String lower = p.getName().toLowerCase(Locale.ROOT);

        async.supply(() -> repo.findByUsernameLower(lower)).thenAccept(opt -> {
            if (opt.isEmpty()) return;
            UserRecord u = opt.get();

            if (!u.has2FA()) {
                async.sync(() -> msg.send(p, "2fa.not-enabled"));
                return;
            }

            boolean valid = false;
            try {
                int numericCode = Integer.parseInt(codeInput.trim());
                valid = gAuth.authorize(u.totpSecret(), numericCode);
            } catch (NumberFormatException ignored) {
            }

            if (!valid) {
                async.sync(() -> msg.send(p, "2fa.disable-fail"));
                return;
            }

            Instant now = Instant.now();
            repo.setTwoFactorEnabled(u.id(), false, now);
            repo.setTotpSecret(u.id(), null, now);
            repo.setBackupCodes(u.id(), null, now);

            async.sync(() -> {
                msg.send(p, "2fa.disable-success");
                if (securityLogger != null) securityLogger.log2FAStateChange(p.getName(), false);
                Bukkit.getPluginManager().callEvent(new Player2FAStateChangeEvent(p, false));
            });
        });
    }

    /** Clean up expired setup tokens. Called periodically. */
    public void cleanupExpiredTokens() {
        long now = System.currentTimeMillis();
        setupTokens.entrySet().removeIf(e -> {
            if (now > e.getValue().expiresAt()) {
                webTokens.remove(e.getValue().webToken());
                return true;
            }
            return false;
        });
    }

    // ---- Backup code helpers ----

    private List<String> generateBackupCodes(int count) {
        List<String> codes = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            codes.add(randomAlphanumeric(8));
        }
        return codes;
    }

    private String randomAlphanumeric(int length) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(secureRandom.nextInt(chars.length())));
        }
        return sb.toString();
    }

    private String generateRandomToken() {
        byte[] bytes = new byte[24];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Check if input matches any backup code in the JSON array of hashes.
     * Returns updated JSON with the used code removed, or null if no match.
     */
    private String checkAndRemoveBackupCode(String input, String codesJson) {
        List<String> hashes = fromJson(codesJson);
        if (hashes == null || hashes.isEmpty()) return null;

        int matchIndex = -1;
        for (int i = 0; i < hashes.size(); i++) {
            if (hasher.verify(input, hashes.get(i))) {
                matchIndex = i;
                break;
            }
        }

        if (matchIndex < 0) return null;

        List<String> updated = new ArrayList<>(hashes);
        updated.remove(matchIndex);
        return toJson(updated);
    }

    // Simple JSON array serialization (no dependency needed)
    private static String toJson(List<String> list) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append("\"").append(list.get(i).replace("\"", "\\\"")).append("\"");
        }
        sb.append("]");
        return sb.toString();
    }

    private static List<String> fromJson(String json) {
        if (json == null || json.isBlank()) return null;
        json = json.trim();
        if (!json.startsWith("[") || !json.endsWith("]")) return null;
        json = json.substring(1, json.length() - 1).trim();
        if (json.isEmpty()) return new ArrayList<>();
        List<String> result = new ArrayList<>();
        // Simple parser for ["value1","value2",...]
        int i = 0;
        while (i < json.length()) {
            while (i < json.length() && (json.charAt(i) == ' ' || json.charAt(i) == ',')) i++;
            if (i >= json.length()) break;
            if (json.charAt(i) == '"') {
                i++; // skip opening quote
                StringBuilder val = new StringBuilder();
                while (i < json.length() && json.charAt(i) != '"') {
                    if (json.charAt(i) == '\\' && i + 1 < json.length()) {
                        i++;
                        val.append(json.charAt(i));
                    } else {
                        val.append(json.charAt(i));
                    }
                    i++;
                }
                if (i < json.length()) i++; // skip closing quote
                result.add(val.toString());
            } else {
                i++;
            }
        }
        return result;
    }

    private static String urlEncode(String s) {
        try {
            return java.net.URLEncoder.encode(s, "UTF-8");
        } catch (Exception e) {
            return s;
        }
    }

    // ---- Inner types ----

    public record SetupToken(String secret, String webToken, long expiresAt, String playerName, List<String> backupCodesPlain) {}

    private static class AttemptTracker {
        int attempts;
        Instant lockoutUntil;
    }
}

