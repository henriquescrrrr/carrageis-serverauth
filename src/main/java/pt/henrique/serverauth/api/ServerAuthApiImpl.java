package pt.henrique.serverauth.api;

import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import pt.henrique.serverauth.auth.AuthService;
import pt.henrique.serverauth.auth.SessionService;
import pt.henrique.serverauth.i18n.MessageService;
import pt.henrique.serverauth.storage.UserRecord;
import pt.henrique.serverauth.storage.UserRepository;
import pt.henrique.serverauth.util.Async;

import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.UUID;

public final class ServerAuthApiImpl implements ServerAuthApi {

    private final AuthService auth;
    private final SessionService sessions;
    private final UserRepository repo;
    private final MessageService msg;
    private final Async async;

    public ServerAuthApiImpl(AuthService auth, SessionService sessions, UserRepository repo, MessageService msg, Async async) {
        this.auth = auth;
        this.sessions = sessions;
        this.repo = repo;
        this.msg = msg;
        this.async = async;
    }

    @Override
    public boolean isRegistered(UUID playerId) {
        Player p = Bukkit.getPlayer(playerId);
        if (p == null) return false;
        Optional<UserRecord> u = repo.findByUsernameLower(p.getName().toLowerCase(Locale.ROOT));
        return u.isPresent() && u.get().isRegistered();
    }

    @Override
    public boolean isPasswordAuthenticated(UUID playerId) {
        return sessions.isPasswordAuthenticated(playerId);
    }

    @Override
    public boolean isFullyAuthenticated(UUID playerId) {
        return sessions.isFullyAuthenticated(playerId);
    }

    @Override
    public boolean is2faEnabled(UUID playerId) {
        Player p = Bukkit.getPlayer(playerId);
        if (p == null) return false;
        Optional<UserRecord> u = repo.findByUsernameLower(p.getName().toLowerCase(Locale.ROOT));
        return u.isPresent() && u.get().has2FA();
    }

    @Override
    public boolean is2faRequired(UUID playerId) {
        Player p = Bukkit.getPlayer(playerId);
        if (p == null) return false;
        Optional<UserRecord> u = repo.findByUsernameLower(p.getName().toLowerCase(Locale.ROOT));
        return u.isPresent() && u.get().twoFactorRequired();
    }

    @Override
    public void set2faRequired(UUID playerId, boolean required) {
        Player p = Bukkit.getPlayer(playerId);
        if (p == null) return;
        async.supply(() -> repo.findByUsernameLower(p.getName().toLowerCase(Locale.ROOT))).thenAccept(opt -> {
            if (opt.isEmpty()) return;
            repo.setTwoFactorRequired(opt.get().id(), required, Instant.now());
        });
    }

    @Override
    public void forceLogout(UUID playerId, String reason) {
        Player p = Bukkit.getPlayer(playerId);
        if (p == null) return;
        sessions.markLoggedOut(playerId);
        async.sync(() -> {
            if (p.isOnline()) {
                msg.send(p, "logout.success");
                if (reason != null && !reason.isBlank()) {
                    p.sendMessage(reason);
                }
            }
        });
    }

    @Override
    public OptionalLong getLast2faSuccessMillis(UUID playerId) {
        Player p = Bukkit.getPlayer(playerId);
        if (p == null) return OptionalLong.empty();
        Optional<UserRecord> u = repo.findByUsernameLower(p.getName().toLowerCase(Locale.ROOT));
        if (u.isEmpty()) return OptionalLong.empty();
        long ms = u.get().lastTwoFactorSuccess().toEpochMilli();
        return ms > 0 ? OptionalLong.of(ms) : OptionalLong.empty();
    }

    @Override
    public int getRemainingLockoutSeconds(UUID playerId) {
        Player p = Bukkit.getPlayer(playerId);
        if (p == null) return 0;
        Optional<UserRecord> u = repo.findByUsernameLower(p.getName().toLowerCase(Locale.ROOT));
        if (u.isEmpty()) return 0;
        Instant lockout = u.get().twoFactorLockoutUntil();
        Instant now = Instant.now();
        if (lockout.isAfter(now)) {
            return (int) Math.max(1, (lockout.toEpochMilli() - now.toEpochMilli()) / 1000);
        }
        return 0;
    }
}

