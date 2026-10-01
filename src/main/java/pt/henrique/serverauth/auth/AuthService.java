package pt.henrique.serverauth.auth;

import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;
import pt.henrique.serverauth.api.events.*;
import pt.henrique.serverauth.config.PluginConfig;
import pt.henrique.serverauth.hook.PlayerSettingsHook;
import pt.henrique.serverauth.i18n.MessageService;
import pt.henrique.serverauth.security.PasswordHasher;
import pt.henrique.serverauth.security.SecurityLogger;
import pt.henrique.serverauth.storage.UserRecord;
import pt.henrique.serverauth.storage.UserRepository;
import pt.henrique.serverauth.util.Async;
import pt.henrique.serverauth.util.IpUtil;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

public final class AuthService {

    private final Plugin plugin;
    private final PluginConfig cfg;
    private final MessageService msg;
    private final Async async;
    private final UserRepository repo;
    private final PasswordHasher hasher;
    private final SessionService sessions;
    private final PlayerSettingsHook settingsHook;

    /** Late-initialized to break circular dependency (AuthService ↔ TwoFactorService). */
    private TwoFactorService twoFactorService;

    /** Late-initialized to break circular dependency (AuthService ↔ LockdownService). */
    private LockdownService lockdownService;

    /** Late-initialized: client fingerprint capture service. */
    private ClientFingerprintService fingerprintService;

    /** Late-initialized: centralised security event logger. */
    private SecurityLogger securityLogger;

    private final ConcurrentHashMap<UUID, Boolean> recoveryChallengePassed = new ConcurrentHashMap<>();
    private final SecureRandom secureRandom = new SecureRandom();

    public AuthService(Plugin plugin, PluginConfig cfg, MessageService msg, Async async,
                       UserRepository repo, PasswordHasher hasher, SessionService sessions,
                       PlayerSettingsHook settingsHook) {
        this.plugin = plugin;
        this.cfg = cfg;
        this.msg = msg;
        this.async = async;
        this.repo = repo;
        this.hasher = hasher;
        this.sessions = sessions;
        this.settingsHook = settingsHook;
    }

    /** Must be called after TwoFactorService is constructed. */
    public void setTwoFactorService(TwoFactorService twoFactorService) {
        this.twoFactorService = twoFactorService;
    }

    /** Must be called after LockdownService is constructed. */
    public void setLockdownService(LockdownService lockdownService) {
        this.lockdownService = lockdownService;
    }

    /** Must be called after ClientFingerprintService is constructed. */
    public void setFingerprintService(ClientFingerprintService fingerprintService) {
        this.fingerprintService = fingerprintService;
    }

    /** Must be called after SecurityLogger is constructed. */
    public void setSecurityLogger(SecurityLogger securityLogger) {
        this.securityLogger = securityLogger;
    }

    /** Returns the fingerprint service (may be null if not yet initialized). */
    public ClientFingerprintService getFingerprintService() {
        return fingerprintService;
    }

    /** Returns true only if fully authenticated (password + 2FA if enabled). */
    public boolean isAuthenticated(Player p) {
        return sessions.isFullyAuthenticated(p.getUniqueId());
    }

    public boolean isPasswordAuthenticated(Player p) {
        return sessions.isPasswordAuthenticated(p.getUniqueId());
    }

    public boolean isTwofaPending(Player p) {
        return sessions.isTwofaPending(p.getUniqueId());
    }

    public CompletableFuture<Optional<UserRecord>> load(Player p) {
        String lower = normalize(p.getName());
        return async.supply(() -> repo.findByUsernameLower(lower));
    }

    public UserRepository repo() { return repo; }
    public PasswordHasher hasher() { return hasher; }
    public Async async() { return async; }

    // ---- join / quit ----

    public void handleJoin(Player p) {
        String ip = IpUtil.ipString(p.getAddress() != null ? p.getAddress().getAddress() : null);
        Instant now = Instant.now();
        String lower = normalize(p.getName());

        // ── Bedrock (Floodgate) auto-login ───────────────────────────────────
        // Floodgate already verified this player's Xbox Live identity before they
        // reached the server, so we trust it and skip register/login/2FA entirely.
        // Bedrock usernames carry Floodgate's prefix, so they never collide with
        // the Java username namespace. No-op for Java players / Floodgate absent.
        if (cfg.floodgate().autoLogin() && FloodgateBridge.isBedrockPlayer(p)) {
            floodgateAutoLogin(p, ip, now, lower);
            return;
        }

        // ── Step 1: drop stale same-JVM session if the current IP doesn't match ──
        // Without this, sessions live forever within a single server run — a player
        // who /loginned from home wifi and reconnects hours later from 5G/school
        // would silently inherit the old session without any re-auth prompt.
        if (cfg.security().sessionRequireIpMatchOnRejoin()
                && sessions.invalidateOnIpMismatch(p.getUniqueId(), ip)) {
            plugin.getLogger().info("[Security] Session dropped for " + p.getName()
                    + " — IP changed (now " + ip + "). Re-auth required.");
            if (securityLogger != null) {
                securityLogger.logSessionIpMismatch(p.getName(), ip);
            }
            if (lockdownService != null) lockdownService.track(p);
        }

        async.supply(() -> repo.findByUsernameLower(lower)).thenAccept(opt -> async.sync(() -> {
            if (!p.isOnline()) return;
            if (opt.isEmpty()) return;

            UserRecord u = opt.get();
            if (u.loginLockoutUntil().isAfter(now)) return;

            // ── Step 2: UUID verification ──
            boolean uuidMismatch = false;
            if (cfg.autoLogin().requireUuidMatch() && u.uuid() != null && !u.uuid().isBlank()) {
                // Record has a stored UUID — compare with current player UUID
                if (!u.uuid().equalsIgnoreCase(p.getUniqueId().toString())) {
                    uuidMismatch = true;
                    if (cfg.autoLogin().logUuidMismatchWarning()) {
                        plugin.getLogger().warning("[Security] UUID mismatch for " + p.getName()
                                + ": expected " + u.uuid() + " got " + p.getUniqueId() + " from IP " + ip);
                    }

                    // Centralised logging + OP notification
                    if (securityLogger != null) {
                        securityLogger.logUuidMismatch(p.getName(), u.uuid(), p.getUniqueId().toString(), ip);
                        securityLogger.notifyOpsUuidMismatch(p.getName(), u.uuid(), p.getUniqueId().toString(), ip);
                    }
                }
            } else if (u.uuid() == null || u.uuid().isBlank()) {
                // No UUID stored yet (pre-V5 account) — backfill
                final long userId = u.id();
                final String playerUuid = p.getUniqueId().toString();
                async.run(() -> repo.updateUuid(userId, playerUuid));
            }

            boolean has2FA = cfg.twoFactor().enabled() && u.has2FA();

            // ── Step 3: Grace period (requires same IP + same UUID) ──
            if (!uuidMismatch && sessions.canUseGrace(p.getUniqueId(), ip, now)) {
                sessions.consumeGrace(p.getUniqueId(), ip, now);
                if (has2FA && !shouldSkip2fa(u, ip, now, p)) {
                    sessions.markTwofaPending(p.getUniqueId());
                    if (wantsLoginNotifications(p)) msg.send(p, "login.grace");
                    msg.send(p, "2fa.verify-prompt");
                    if (securityLogger != null) securityLogger.logGraceLogin(p.getName(), ip);
                    Bukkit.getPluginManager().callEvent(new Player2FAPendingEvent(p));
                } else {
                    sessions.markLoggedIn(p.getUniqueId(), ip, now);
                    if (lockdownService != null) lockdownService.restoreAndUntrack(p);
                    if (wantsLoginNotifications(p)) msg.send(p, "login.grace");
                    if (securityLogger != null) securityLogger.logGraceLogin(p.getName(), ip);
                    onAuthenticationSuccess(p, u, ip);
                    Bukkit.getPluginManager().callEvent(new PlayerFullyAuthenticatedEvent(p));
                }
                return;
            }

            // ── Step 4: Auto-login (4-layer, delayed) ──
            // If UUID mismatched, deny all automatic login — player must /login manually
            if (uuidMismatch) {
                msg.send(p, "login.uuid-mismatch");
                return;
            }

            // Layer 1 (username) + Layer 2 (UUID) already verified above.
            // Layer 3 (IP) + Layer 4 (fingerprint) require a delay for fingerprint data to arrive.
            if (u.autologinEnabled() && (!cfg.autoLogin().requireIpMatch() || isTrustedIp(u, ip))) {
                // Delay the fingerprint check to allow client brand to arrive
                final UserRecord finalU = u;
                final boolean finalHas2FA = has2FA;
                final int delayTicks = cfg.autoLogin().delayTicks();
                Bukkit.getScheduler().runTaskLater(plugin, () -> {
                    if (!p.isOnline()) return;
                    if (sessions.isLoggedIn(p.getUniqueId())) return; // already logged in

                    // Layer 4: Client fingerprint check (only if configured to enforce)
                    boolean fingerprintOk = true;
                    if (cfg.autoLogin().requireFingerprintMatch()
                            && fingerprintService != null
                            && finalU.lastClientFingerprint() != null
                            && !finalU.lastClientFingerprint().isEmpty()) {
                        String currentFp = fingerprintService.getFingerprint(p.getUniqueId());
                        fingerprintOk = configAwareFingerprintMatch(
                                finalU.lastClientFingerprint(), currentFp);
                        if (!fingerprintOk && cfg.autoLogin().logFingerprintMismatch()) {
                            plugin.getLogger().info("[Security] Fingerprint mismatch for " + p.getName()
                                    + ": stored=" + finalU.lastClientFingerprint()
                                    + " current=" + currentFp);
                            if (securityLogger != null) securityLogger.logFingerprintMismatch(
                                    p.getName(), finalU.lastClientFingerprint(), currentFp);
                        }
                    }

                    if (cfg.autoLogin().debugAutologin()) {
                        plugin.getLogger().info("[AutoLogin-Debug] " + p.getName()
                                + " — IP=" + ip + " fingerprintOk=" + fingerprintOk);
                    }

                    if (!fingerprintOk) {
                        msg.send(p, "login.fingerprint-mismatch");
                        if (securityLogger != null) securityLogger.logAutoLoginDenied(p.getName(), ip, "fingerprint_mismatch");
                        return; // Deny auto-login, player must /login manually
                    }

                    // All 4 layers passed — auto-login accepted
                    if (finalHas2FA && !shouldSkip2fa(finalU, ip, now, p)) {
                        sessions.markTwofaPending(p.getUniqueId());
                        if (wantsLoginNotifications(p)) msg.send(p, "login.autologin");
                        msg.send(p, "2fa.verify-prompt");
                        if (securityLogger != null) securityLogger.logAutoLogin(p.getName(), ip);
                        Bukkit.getPluginManager().callEvent(new Player2FAPendingEvent(p));
                    } else {
                        sessions.markLoggedIn(p.getUniqueId(), ip, now);
                        if (lockdownService != null) lockdownService.restoreAndUntrack(p);
                        if (wantsLoginNotifications(p)) msg.send(p, "login.autologin");
                        if (securityLogger != null) securityLogger.logAutoLogin(p.getName(), ip);
                        onAuthenticationSuccess(p, finalU, ip);
                        Bukkit.getPluginManager().callEvent(new PlayerFullyAuthenticatedEvent(p));
                    }
                }, delayTicks);
            }
        }));
    }

    /**
     * Called after any successful authentication (manual login, auto-login, grace).
     * Updates the client fingerprint and UUID in the database.
     */
    /** Auto-login a Bedrock (Floodgate) player: load-or-create their account on
     *  the async pool, then mark the session authenticated on the main thread.
     *  Mirrors register()'s threading split (DB off-thread, Bukkit/session on-thread). */
    private void floodgateAutoLogin(Player p, String ip, Instant now, String lower) {
        async.supply(() -> {
            UserRecord u = repo.findByUsernameLower(lower).orElse(null);
            if (u == null) {
                // First Bedrock join — auto-register. The password is random and
                // never used (Floodgate's Xbox auth IS the verification).
                String hash = hasher.hash(java.util.UUID.randomUUID().toString());
                u = repo.createUser(p.getName(), lower, hash, now);
                repo.updateUuid(u.id(), p.getUniqueId().toString());
            } else if (u.uuid() == null || u.uuid().isBlank()) {
                repo.updateUuid(u.id(), p.getUniqueId().toString());
            }
            repo.updateLastLogin(u.id(), now, ip);
            repo.resetLoginAttempts(u.id(), now);
            return u;
        }).thenAccept(u -> async.sync(() -> {
            if (!p.isOnline() || u == null) return;
            sessions.markLoggedIn(p.getUniqueId(), ip, now);
            if (lockdownService != null) lockdownService.restoreAndUntrack(p);
            if (securityLogger != null) securityLogger.logRegistration(p.getName(), ip);
            onAuthenticationSuccess(p, u, ip);
            Bukkit.getPluginManager().callEvent(new PlayerAuthSuccessEvent(p));
            Bukkit.getPluginManager().callEvent(new PlayerFullyAuthenticatedEvent(p));
        })).exceptionally(ex -> {
            plugin.getLogger().warning("[Floodgate] auto-login failed for " + p.getName() + ": " + ex.getMessage());
            return null;
        });
    }

    private void onAuthenticationSuccess(Player p, UserRecord record, String ip) {
        if (fingerprintService == null) return;

        String currentFingerprint = fingerprintService.getFingerprint(p.getUniqueId());
        String currentBrand = fingerprintService.getBrand(p.getUniqueId());
        String currentSettingsHash = fingerprintService.getSettingsHash(p.getUniqueId());

        async.run(() -> {
            // Update fingerprint in DB
            repo.updateClientFingerprint(record.id(), currentBrand, currentSettingsHash, currentFingerprint);

            // Backfill UUID if null
            if (record.uuid() == null || record.uuid().isEmpty()) {
                repo.updateUuid(record.id(), p.getUniqueId().toString());
            }
        });
    }

    public void handleQuit(Player p) {
        String ip = IpUtil.ipString(p.getAddress() != null ? p.getAddress().getAddress() : null);
        sessions.recordQuit(p.getUniqueId(), ip, Instant.now());

        String lower = normalize(p.getName());
        async.supply(() -> repo.findByUsernameLower(lower)).thenAccept(opt -> {
            if (opt.isEmpty()) return;
            repo.updateLastSessionTime(opt.get().id(), Instant.now());
        });
    }

    // ---- register ----

    public void register(Player p, String pw, String confirm) {
        if (!meetsPasswordPolicy(pw)) {
            msg.send(p, "register.password-too-short", Map.of("min", String.valueOf(cfg.password().minLength())));
            return;
        }
        if (cfg.password().requireConfirmMatch() && !pw.equals(confirm)) {
            msg.send(p, "register.password-mismatch");
            return;
        }

        String lower = normalize(p.getName());
        Instant now = Instant.now();
        String ip = IpUtil.ipString(p.getAddress() != null ? p.getAddress().getAddress() : null);

        async.supply(() -> repo.findByUsernameLower(lower)).thenAccept(opt -> {
            if (opt.isPresent()) {
                async.sync(() -> msg.send(p, "register.already-registered"));
                return;
            }

            // Enforce max accounts per IP (mainly useful on offline-mode servers to limit mass registration)
            int maxPerIp = cfg.policy().maxAccountsPerIp();
            if (maxPerIp > 0 && ip != null && !ip.isBlank() && repo.countAccountsByIp(ip) >= maxPerIp) {
                plugin.getLogger().info("[Security] Registration blocked for " + p.getName()
                        + " — IP " + ip + " already has " + maxPerIp + " account(s).");
                async.sync(() -> msg.send(p, "register.max-accounts-per-ip", Map.of("max", String.valueOf(maxPerIp))));
                return;
            }

            String hash = hasher.hash(pw);
            UserRecord created = repo.createUser(p.getName(), lower, hash, now);
            // Store UUID on registration
            repo.updateUuid(created.id(), p.getUniqueId().toString());
            repo.updateLastLogin(created.id(), now, ip);
            repo.resetLoginAttempts(created.id(), now);

            async.sync(() -> {
                sessions.markLoggedIn(p.getUniqueId(), ip, now);
                if (lockdownService != null) lockdownService.restoreAndUntrack(p);
                msg.send(p, "register.success");
                msg.send(p, "recovery-recommend.line1");
                msg.send(p, "recovery-recommend.line2");
                if (securityLogger != null) securityLogger.logRegistration(p.getName(), ip);
                onAuthenticationSuccess(p, created, ip);
                Bukkit.getPluginManager().callEvent(new PlayerAuthSuccessEvent(p));
                Bukkit.getPluginManager().callEvent(new PlayerFullyAuthenticatedEvent(p));
            });
        }).exceptionally(ex -> {
            plugin.getLogger().warning("Register failed: " + ex.getMessage());
            return null;
        });
    }

    // ---- login (2FA-aware) ----

    public void login(Player p, String pw) {
        String lower = normalize(p.getName());
        String ip = IpUtil.ipString(p.getAddress() != null ? p.getAddress().getAddress() : null);
        Instant now = Instant.now();

        async.supply(() -> repo.findByUsernameLower(lower)).thenAccept(opt -> {
            if (opt.isEmpty()) {
                async.sync(() -> msg.send(p, "login.not-registered"));
                return;
            }

            UserRecord u = opt.get();

            if (u.loginLockoutUntil().isAfter(now)) {
                long seconds = Math.max(1, (u.loginLockoutUntil().toEpochMilli() - now.toEpochMilli()) / 1000);
                async.sync(() -> msg.send(p, "errors.locked-out-login", Map.of("seconds", String.valueOf(seconds))));
                return;
            }

            boolean ok = hasher.verify(pw, u.passwordHash());
            if (!ok) {
                Instant lockoutUntil = now.plusSeconds(cfg.security().loginLockoutSeconds());
                int newAttempts = u.loginAttempts() + 1;
                repo.incrementLoginAttempts(u.id(), cfg.security().maxLoginAttempts(), lockoutUntil, now);
                if (securityLogger != null) securityLogger.logLoginFailure(p.getName(), ip);

                // Kick player after max attempts if configured
                if (cfg.security().kickOnMaxAttempts() && newAttempts >= cfg.security().maxLoginAttempts()) {
                    if (securityLogger != null) securityLogger.logMaxAttemptsKick(p.getName(), ip);
                    async.sync(() -> {
                        if (p.isOnline()) {
                            p.kick(net.kyori.adventure.text.Component.text(
                                    msg.raw(p, "errors.locked-out-login")
                                            .replace("{seconds}", String.valueOf(cfg.security().loginLockoutSeconds()))));
                        }
                    });
                } else {
                    async.sync(() -> msg.send(p, "login.wrong-password"));
                }
                return;
            }

            repo.resetLoginAttempts(u.id(), now);
            repo.updateLastLogin(u.id(), now, ip);
            if (u.autologinEnabled()) {
                repo.updateTrustedIpScore(u.id(), ip, now);
            }

            // On successful manual login, ALWAYS update UUID to current player's UUID.
            // This handles: (a) backfill for pre-V5 accounts, (b) legitimate name changes
            // where the same person reclaims their account with a new UUID.
            repo.updateUuid(u.id(), p.getUniqueId().toString());

            boolean needs2FA = cfg.twoFactor().enabled() && u.has2FA();
            boolean policyBlocked = false;
            if (cfg.twoFactor().enabled() && cfg.policy().opsRequire2FA()) {
                if ((u.twoFactorRequired() || isOpByName(p.getName())) && !u.has2FA()) {
                    policyBlocked = true;
                }
            }

            // Check if we can skip 2FA for same-IP logins
            boolean skip2FA = needs2FA && shouldSkip2fa(u, ip, now, p);

            final boolean finalPolicyBlocked = policyBlocked;
            final boolean finalSkip2FA = skip2FA;

            async.sync(() -> {
                recoveryChallengePassed.remove(p.getUniqueId());
                Bukkit.getPluginManager().callEvent(new PlayerAuthSuccessEvent(p));

                if (needs2FA && !finalSkip2FA) {
                    sessions.markTwofaPending(p.getUniqueId());
                    if (wantsLoginNotifications(p)) msg.send(p, "login.success");
                    msg.send(p, "2fa.verify-prompt");
                    if (securityLogger != null) securityLogger.logLoginSuccess(p.getName(), ip);
                    Bukkit.getPluginManager().callEvent(new Player2FAPendingEvent(p));
                } else if (finalPolicyBlocked) {
                    sessions.markTwofaPending(p.getUniqueId());
                    if (wantsLoginNotifications(p)) msg.send(p, "login.success");
                    msg.send(p, "2fa.ops-require-setup");
                    if (securityLogger != null) securityLogger.logLoginSuccess(p.getName(), ip);
                    Bukkit.getPluginManager().callEvent(new Player2FAPendingEvent(p));
                } else {
                    sessions.markLoggedIn(p.getUniqueId(), ip, now);
                    if (lockdownService != null) lockdownService.restoreAndUntrack(p);
                    if (wantsLoginNotifications(p)) msg.send(p, "login.success");
                    if (securityLogger != null) securityLogger.logLoginSuccess(p.getName(), ip);
                    onAuthenticationSuccess(p, u, ip);
                    Bukkit.getPluginManager().callEvent(new PlayerFullyAuthenticatedEvent(p));
                }
            });
        }).exceptionally(ex -> {
            plugin.getLogger().warning("Login failed: " + ex.getMessage());
            return null;
        });
    }

    private boolean isOpByName(String name) {
        Player p = Bukkit.getPlayerExact(name);
        return p != null && p.isOp();
    }

    // ---- logout ----

    public void logout(Player p) {
        sessions.markLoggedOut(p.getUniqueId());
        recoveryChallengePassed.remove(p.getUniqueId());
        if (securityLogger != null) securityLogger.logLogout(p.getName());
        msg.send(p, "logout.success");
    }

    // ---- change password ----

    public void changePassword(Player p, String oldPw, String newPw, String confirm) {
        if (!meetsPasswordPolicy(newPw)) {
            msg.send(p, "register.password-too-short", Map.of("min", String.valueOf(cfg.password().minLength())));
            return;
        }
        if (cfg.password().requireConfirmMatch() && !newPw.equals(confirm)) {
            msg.send(p, "register.password-mismatch");
            return;
        }

        String lower = normalize(p.getName());
        Instant now = Instant.now();

        async.supply(() -> repo.findByUsernameLower(lower)).thenAccept(opt -> {
            if (opt.isEmpty()) {
                async.sync(() -> msg.send(p, "errors.must-register"));
                return;
            }
            UserRecord u = opt.get();
            if (!hasher.verify(oldPw, u.passwordHash())) {
                async.sync(() -> msg.send(p, "changepassword.wrong-old"));
                return;
            }
            String hash = hasher.hash(newPw);
            repo.updatePasswordHash(u.id(), hash, now);
            if (securityLogger != null) securityLogger.logPasswordChange(p.getName(), p.getName());
            async.sync(() -> msg.send(p, "changepassword.success"));
        });
    }

    // ---- autologin ----

    public void setAutologin(Player p, boolean enabled) {
        if (!isAuthenticated(p)) { msg.send(p, "errors.must-login"); return; }
        String lower = normalize(p.getName());
        Instant now = Instant.now();
        async.supply(() -> repo.findByUsernameLower(lower)).thenAccept(opt -> {
            if (opt.isEmpty()) return;
            repo.setAutoLoginEnabled(opt.get().id(), enabled, now);
            async.sync(() -> msg.send(p, enabled ? "autologin.enabled" : "autologin.disabled"));
        });
    }

    public void autologinStatus(Player p) {
        String lower = normalize(p.getName());
        async.supply(() -> repo.findByUsernameLower(lower)).thenAccept(opt -> async.sync(() -> {
            if (opt.isEmpty()) { msg.send(p, "errors.must-register"); return; }
            msg.send(p, opt.get().autologinEnabled() ? "autologin.status-on" : "autologin.status-off");
        }));
    }

    // ---- recovery ----

    public void recoveryStatus(Player p) {
        if (!isAuthenticated(p)) { msg.send(p, "errors.must-login"); return; }
        String lower = normalize(p.getName());
        async.supply(() -> repo.findByUsernameLower(lower)).thenAccept(opt -> async.sync(() -> {
            if (opt.isEmpty() || !opt.get().hasRecovery()) { msg.send(p, "recovery.status-none"); }
            else { msg.send(p, "recovery.status-ok"); }
        }));
    }

    public void setRecoveryQuestion(Player p, String question) {
        if (!isAuthenticated(p)) { msg.send(p, "errors.must-login"); return; }
        if (question == null || question.isBlank()) { msg.send(p, "recovery.setquestion-usage"); return; }
        String lower = normalize(p.getName());
        Instant now = Instant.now();
        async.supply(() -> repo.findByUsernameLower(lower)).thenAccept(opt -> {
            if (opt.isEmpty()) return;
            repo.setRecoveryQuestion(opt.get().id(), question, now);
            async.sync(() -> msg.send(p, "recovery.setquestion-success"));
        });
    }

    public void setRecoveryAnswer(Player p, String answer) {
        if (!isAuthenticated(p)) { msg.send(p, "errors.must-login"); return; }
        if (answer == null || answer.isBlank()) { msg.send(p, "recovery.setanswer-usage"); return; }
        String lower = normalize(p.getName());
        Instant now = Instant.now();
        async.supply(() -> repo.findByUsernameLower(lower)).thenAccept(opt -> {
            if (opt.isEmpty()) return;
            UserRecord u = opt.get();
            if (u.recoveryQuestion() == null || u.recoveryQuestion().isBlank()) {
                async.sync(() -> msg.send(p, "recovery.must-set-question-first"));
                return;
            }
            String hash = hasher.hash(answer);
            repo.setRecoveryAnswerHash(u.id(), hash, now);
            async.sync(() -> msg.send(p, "recovery.setanswer-success"));
        });
    }

    public void recoverShowQuestion(Player p) {
        String lower = normalize(p.getName());
        async.supply(() -> repo.findByUsernameLower(lower)).thenAccept(opt -> async.sync(() -> {
            if (opt.isEmpty()) { msg.send(p, "recover.not-registered"); return; }
            UserRecord u = opt.get();
            // If 2FA is enabled, recovery uses 2FA code instead of questions
            if (cfg.twoFactor().enabled() && u.has2FA()) {
                msg.send(p, "recover.use-2fa-code");
                return;
            }
            if (!u.hasRecovery()) {
                msg.send(p, "recover.no-recovery");
                return;
            }
            msg.send(p, "recover.question", Map.of("question", u.recoveryQuestion()));
            msg.send(p, "recover.answer-hint");
        }));
    }

    /**
     * Recovery via 2FA code. When 2FA is enabled, this replaces the question/answer flow.
     */
    public void recoverWith2FA(Player p, String codeInput) {
        String lower = normalize(p.getName());
        Instant now = Instant.now();
        async.supply(() -> repo.findByUsernameLower(lower)).thenAccept(opt -> {
            if (opt.isEmpty()) {
                async.sync(() -> msg.send(p, "recover.no-recovery"));
                return;
            }
            UserRecord u = opt.get();
            if (!cfg.twoFactor().enabled() || !u.has2FA()) {
                async.sync(() -> msg.send(p, "recover.no-2fa-use-questions"));
                return;
            }

            // Rate-limit brute-force of the recovery 2FA code. Without this, /recover 2fa
            // is an unlimited TOTP-verification oracle — unlike /login and the question-based
            // recovery, which both lock out. Shares the recovery lockout counter.
            if (u.recoveryLockoutUntil().isAfter(now)) {
                long seconds = Math.max(1, (u.recoveryLockoutUntil().toEpochMilli() - now.toEpochMilli()) / 1000);
                async.sync(() -> msg.send(p, "errors.locked-out-recovery", Map.of("seconds", String.valueOf(seconds))));
                return;
            }

            // Verify TOTP code
            boolean success = false;
            try {
                int numericCode = Integer.parseInt(codeInput.trim());
                success = twoFactorService.verifyTotpCode(u.totpSecret(), numericCode);
            } catch (NumberFormatException ignored) {}

            if (success) {
                repo.resetRecoveryAttempts(u.id(), now);
                recoveryChallengePassed.put(p.getUniqueId(), true);
                async.sync(() -> msg.send(p, "recover.2fa-accepted"));
            } else {
                Instant lockoutUntil = now.plusSeconds(cfg.security().recoveryLockoutSeconds());
                repo.incrementRecoveryAttempts(u.id(), cfg.security().maxRecoveryAttempts(), lockoutUntil, now);
                String ip = IpUtil.ipString(p.getAddress() != null ? p.getAddress().getAddress() : null);
                if (securityLogger != null) securityLogger.log2FAFailure(p.getName(), ip);
                async.sync(() -> msg.send(p, "recover.2fa-wrong"));
            }
        });
    }

    public void recoverAnswer(Player p, String answer) {
        String lower = normalize(p.getName());
        Instant now = Instant.now();
        async.supply(() -> repo.findByUsernameLower(lower)).thenAccept(opt -> {
            if (opt.isEmpty() || !opt.get().hasRecovery()) {
                async.sync(() -> msg.send(p, "recover.no-recovery"));
                return;
            }
            UserRecord u = opt.get();
            if (u.recoveryLockoutUntil().isAfter(now)) {
                long seconds = Math.max(1, (u.recoveryLockoutUntil().toEpochMilli() - now.toEpochMilli()) / 1000);
                async.sync(() -> msg.send(p, "errors.locked-out-recovery", Map.of("seconds", String.valueOf(seconds))));
                return;
            }
            boolean ok = hasher.verify(answer, u.recoveryAnswerHash());
            if (!ok) {
                Instant lockoutUntil = now.plusSeconds(cfg.security().recoveryLockoutSeconds());
                repo.incrementRecoveryAttempts(u.id(), cfg.security().maxRecoveryAttempts(), lockoutUntil, now);
                async.sync(() -> msg.send(p, "recover.answer-wrong"));
                return;
            }
            repo.resetRecoveryAttempts(u.id(), now);
            recoveryChallengePassed.put(p.getUniqueId(), true);
            async.sync(() -> msg.send(p, "recover.answer-correct"));
        });
    }

    public void recoverSetPassword(Player p, String newPw, String confirm) {
        if (!recoveryChallengePassed.getOrDefault(p.getUniqueId(), false)) {
            msg.send(p, "recover.must-verify-first"); return;
        }
        if (!meetsPasswordPolicy(newPw)) {
            msg.send(p, "register.password-too-short", Map.of("min", String.valueOf(cfg.password().minLength()))); return;
        }
        if (cfg.password().requireConfirmMatch() && !newPw.equals(confirm)) {
            msg.send(p, "register.password-mismatch"); return;
        }
        String lower = normalize(p.getName());
        Instant now = Instant.now();
        async.supply(() -> repo.findByUsernameLower(lower)).thenAccept(opt -> {
            if (opt.isEmpty()) return;
            String hash = hasher.hash(newPw);
            repo.updatePasswordHash(opt.get().id(), hash, now);
            recoveryChallengePassed.remove(p.getUniqueId());
            sessions.markLoggedOut(p.getUniqueId());
            String rip = IpUtil.ipString(p.getAddress() != null ? p.getAddress().getAddress() : null);
            if (securityLogger != null) securityLogger.logAccountRecovery(p.getName(), rip);
            async.sync(() -> msg.send(p, "recover.setpassword-success"));
        });
    }

    // ---- help state ----

    /**
     * Resolves the help state off the main thread. {@code /authhelp} is reachable before a
     * player authenticates, so a synchronous lookup here lets an unauthenticated connection
     * drive a database round-trip on the server thread on every invocation.
     */
    public CompletableFuture<AuthHelpState> helpState(Player p) {
        if (isTwofaPending(p)) return CompletableFuture.completedFuture(AuthHelpState.TWO_FA_PENDING);
        String lower = normalize(p.getName());
        return async.supply(() -> repo.findByUsernameLower(lower)).thenApply(u -> {
            if (u.isEmpty()) return AuthHelpState.UNREGISTERED;
            return isAuthenticated(p) ? AuthHelpState.LOGGED_IN : AuthHelpState.LOCKED;
        });
    }

    // ---- admin operations (all require admin's own 2FA code) ----

    /**
     * Verifies the admin's own 2FA code. Returns true if valid.
     * This is the gatekeeper for ALL admin operations.
     */
    public CompletableFuture<Boolean> verifyAdmin2FA(Player admin, String codeInput) {
        String lower = normalize(admin.getName());
        return async.supply(() -> {
            Optional<UserRecord> opt = repo.findByUsernameLower(lower);
            if (opt.isEmpty()) return false;
            UserRecord u = opt.get();
            if (!u.has2FA()) return false;
            try {
                int numericCode = Integer.parseInt(codeInput.trim());
                return twoFactorService.verifyTotpCode(u.totpSecret(), numericCode);
            } catch (NumberFormatException e) {
                return false;
            }
        });
    }

    /** Admin: look up a player's registration info (never reveals the actual password). */
    public void adminLookup(Player admin, String targetName) {
        String lower = normalize(targetName);
        async.supply(() -> repo.findByUsernameLower(lower)).thenAccept(opt -> async.sync(() -> {
            if (opt.isEmpty()) {
                msg.send(admin, "admin.player-not-found", Map.of("player", targetName));
                return;
            }
            UserRecord u = opt.get();
            msg.send(admin, "admin.lookup-header", Map.of("player", u.usernameOriginal()));
            msg.send(admin, "admin.lookup-registered", Map.of("value", u.isRegistered() ? "Yes" : "No"));
            msg.send(admin, "admin.lookup-2fa", Map.of("value", u.has2FA() ? "Enabled" : "Disabled"));
            msg.send(admin, "admin.lookup-recovery", Map.of("value", u.hasRecovery() ? "Configured" : "Not set"));
            msg.send(admin, "admin.lookup-autologin", Map.of("value", u.autologinEnabled() ? "ON" : "OFF"));
            msg.send(admin, "admin.lookup-last-ip", Map.of("value", u.lastIp() != null ? u.lastIp() : "unknown"));
        }));
    }

    /** Admin: set a player's password (requires admin 2FA). */
    public void adminSetPassword(Player admin, String targetName, String newPw, String adminCode) {
        verifyAdmin2FA(admin, adminCode).thenAccept(valid -> {
            if (!valid) {
                async.sync(() -> msg.send(admin, "admin.2fa-failed"));
                return;
            }
            String lower = normalize(targetName);
            async.supply(() -> repo.findByUsernameLower(lower)).thenAccept(opt -> {
                if (opt.isEmpty()) {
                    async.sync(() -> msg.send(admin, "admin.player-not-found", Map.of("player", targetName)));
                    return;
                }
                UserRecord u = opt.get();
                if (!meetsPasswordPolicy(newPw)) {
                    async.sync(() -> msg.send(admin, "register.password-too-short",
                            Map.of("min", String.valueOf(cfg.password().minLength()))));
                    return;
                }
                String hash = hasher.hash(newPw);
                repo.updatePasswordHash(u.id(), hash, Instant.now());
                if (securityLogger != null) securityLogger.logAdminAction(admin.getName(), "setpassword", u.usernameOriginal());
                // Force logout the target player
                Player target = org.bukkit.Bukkit.getPlayerExact(targetName);
                if (target != null && target.isOnline()) {
                    async.sync(() -> {
                        sessions.markLoggedOut(target.getUniqueId());
                        msg.send(target, "admin.your-password-changed");
                    });
                }
                async.sync(() -> msg.send(admin, "admin.setpassword-success", Map.of("player", u.usernameOriginal())));
            });
        });
    }

    /** Admin: delete a player's account (unregister — requires admin 2FA). */
    public void adminDeleteAccount(Player admin, String targetName, String adminCode) {
        verifyAdmin2FA(admin, adminCode).thenAccept(valid -> {
            if (!valid) {
                async.sync(() -> msg.send(admin, "admin.2fa-failed"));
                return;
            }
            String lower = normalize(targetName);
            async.supply(() -> repo.findByUsernameLower(lower)).thenAccept(opt -> {
                if (opt.isEmpty()) {
                    async.sync(() -> msg.send(admin, "admin.player-not-found", Map.of("player", targetName)));
                    return;
                }
                UserRecord u = opt.get();
                repo.deleteUser(u.id());
                if (securityLogger != null) securityLogger.logAdminAction(admin.getName(), "delete", u.usernameOriginal());
                // Force logout the target player
                Player target = org.bukkit.Bukkit.getPlayerExact(targetName);
                if (target != null && target.isOnline()) {
                    async.sync(() -> {
                        sessions.markLoggedOut(target.getUniqueId());
                        msg.send(target, "admin.your-account-deleted");
                    });
                }
                async.sync(() -> msg.send(admin, "admin.delete-success", Map.of("player", u.usernameOriginal())));
            });
        });
    }

    /** Admin: reset a player's 2FA (requires admin 2FA). */
    public void adminReset2FA(Player admin, String targetName, String adminCode) {
        verifyAdmin2FA(admin, adminCode).thenAccept(valid -> {
            if (!valid) {
                async.sync(() -> msg.send(admin, "admin.2fa-failed"));
                return;
            }
            String lower = normalize(targetName);
            async.supply(() -> repo.findByUsernameLower(lower)).thenAccept(opt -> {
                if (opt.isEmpty()) {
                    async.sync(() -> msg.send(admin, "admin.player-not-found", Map.of("player", targetName)));
                    return;
                }
                UserRecord u = opt.get();
                if (!u.has2FA()) {
                    async.sync(() -> msg.send(admin, "admin.2fa-not-active", Map.of("player", u.usernameOriginal())));
                    return;
                }
                Instant now = Instant.now();
                repo.setTwoFactorEnabled(u.id(), false, now);
                repo.setTotpSecret(u.id(), null, now);
                repo.setBackupCodes(u.id(), null, now);
                repo.updateLast2faVerifiedIp(u.id(), null, now);
                if (securityLogger != null) securityLogger.logAdminAction(admin.getName(), "reset2fa", u.usernameOriginal());
                // Force logout the target player
                Player target = org.bukkit.Bukkit.getPlayerExact(targetName);
                if (target != null && target.isOnline()) {
                    async.sync(() -> {
                        sessions.markLoggedOut(target.getUniqueId());
                        msg.send(target, "admin.your-2fa-reset");
                    });
                }
                async.sync(() -> msg.send(admin, "admin.reset2fa-success", Map.of("player", u.usernameOriginal())));
            });
        });
    }

    // ---- helpers ----

    /**
     * Determines if 2FA can be skipped for this login based on IP-match settings.
     * Only applies when require-only-on-ip-change is enabled.
     */
    private boolean shouldSkip2fa(UserRecord u, String ip, Instant now, Player p) {
        if (!cfg.twoFactor().requireOnlyOnIpChange()) return false;

        String lastVerifiedIp = u.last2faVerifiedIp();
        if (lastVerifiedIp == null || lastVerifiedIp.isBlank()) return false;
        if (ip == null || ip.isBlank()) return false;
        if (!IpUtil.ipEquals(lastVerifiedIp, ip)) return false;

        // IP matches — check max trusted session hours
        int maxHours = cfg.twoFactor().maxTrustedSessionHours();
        if (maxHours > 0) {
            Instant lastSuccess = u.lastTwoFactorSuccess();
            if (lastSuccess == null || lastSuccess.equals(Instant.EPOCH)) return false;
            long hoursSince = Duration.between(lastSuccess, now).toHours();
            if (hoursSince >= maxHours) return false;
        }

        // Optional random challenge (1 in N)
        if (cfg.twoFactor().sameIpRandomChallengeEnabled()) {
            int n = cfg.twoFactor().sameIpRandomChallengeOneInN();
            if (secureRandom.nextInt(n) == 0) {
                if (cfg.twoFactor().debugSkipMessages()) {
                    plugin.getLogger().info("[2FA-Debug] Random challenge triggered for " + p.getName());
                }
                return false; // Force 2FA this time
            }
        }

        if (cfg.twoFactor().debugSkipMessages()) {
            plugin.getLogger().info("[2FA-Debug] Skipping 2FA for " + p.getName() + " (same IP)");
        }

        return true;
    }

    private boolean isTrustedIp(UserRecord u, String ip) {
        if (ip == null || ip.isBlank()) return false;
        return IpUtil.ipEquals(ip, u.trustedIp1()) || IpUtil.ipEquals(ip, u.trustedIp2());
    }

    /**
     * Fingerprint match that respects the fingerprint config (enforce-brand, enforce-settings).
     * If enforce-brand is false, only the settings hash is checked (and vice versa).
     */
    private boolean configAwareFingerprintMatch(String storedFingerprint, String currentFingerprint) {
        if (storedFingerprint == null || storedFingerprint.isEmpty()) return true;
        if (currentFingerprint == null) return true;

        String[] stored = storedFingerprint.split(":", 2);
        String[] current = currentFingerprint.split(":", 2);

        // Brand check
        if (cfg.fingerprint().enforceBrand()) {
            String storedBrand = stored.length > 0 ? stored[0] : "unknown";
            String currentBrand = current.length > 0 ? current[0] : "unknown";
            if (!"unknown".equals(storedBrand) && !"unknown".equals(currentBrand)) {
                if (!storedBrand.equalsIgnoreCase(currentBrand)) return false;
            }
        }

        // Settings hash check
        if (cfg.fingerprint().enforceSettings()) {
            String storedHash = stored.length > 1 ? stored[1] : "unknown";
            String currentHash = current.length > 1 ? current[1] : "unknown";
            if (!"unknown".equals(storedHash) && !"unknown".equals(currentHash)) {
                if (!storedHash.equalsIgnoreCase(currentHash)) return false;
            }
        }

        return true;
    }

    private boolean meetsPasswordPolicy(String pw) {
        return pw != null && pw.length() >= cfg.password().minLength();
    }

    /** Whether the player wants login/autologin/grace notifications (PlayerSettings preference). */
    private boolean wantsLoginNotifications(Player p) {
        return settingsHook == null || settingsHook.getSetting(p.getUniqueId(), "serverauth.login-notifications", true);
    }

    private static String normalize(String name) {
        return name == null ? "" : name.toLowerCase(Locale.ROOT);
    }


    public enum AuthHelpState { UNREGISTERED, LOCKED, TWO_FA_PENDING, LOGGED_IN }
}

