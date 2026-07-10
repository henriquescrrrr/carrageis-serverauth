package pt.henrique.serverauth.auth;

import pt.henrique.serverauth.config.PluginConfig;
import pt.henrique.serverauth.util.IpUtil;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public final class SessionService {

    private final PluginConfig cfg;

    private final Map<UUID, Session> liveSessions = new ConcurrentHashMap<>();
    private final Map<UUID, Grace> grace = new ConcurrentHashMap<>();
    private final Set<UUID> twofaPending = ConcurrentHashMap.newKeySet();

    public SessionService(PluginConfig cfg) {
        this.cfg = cfg;
    }

    public boolean isLoggedIn(UUID uuid) {
        Session s = liveSessions.get(uuid);
        if (s == null) return false;
        if (isExpired(s.authenticatedAt())) {
            liveSessions.remove(uuid);
            return false;
        }
        return true;
    }

    /** IP recorded when the session was last authenticated. Empty string if no session. */
    public String sessionIp(UUID uuid) {
        Session s = liveSessions.get(uuid);
        return s == null ? "" : s.ip();
    }

    /**
     * Drop the in-memory session if it exists but the recorded IP doesn't match
     * {@code currentIp}. Returns true when a mismatch was detected (and the
     * session was invalidated), false otherwise. Used by AuthService.handleJoin
     * to force re-auth when the player comes back from a different network.
     */
    public boolean invalidateOnIpMismatch(UUID uuid, String currentIp) {
        Session s = liveSessions.get(uuid);
        if (s == null) return false;
        if (currentIp == null || currentIp.isBlank()) return false;
        if (safeIpMatch(s.ip(), currentIp)) return false;
        liveSessions.remove(uuid);
        grace.remove(uuid);
        twofaPending.remove(uuid);
        return true;
    }

    /** Password authenticated (either fully logged in or pending 2FA). */
    public boolean isPasswordAuthenticated(UUID uuid) {
        return isLoggedIn(uuid) || twofaPending.contains(uuid);
    }

    /** Fully authenticated: password OK and 2FA verified (or no 2FA). */
    public boolean isFullyAuthenticated(UUID uuid) {
        return isLoggedIn(uuid) && !twofaPending.contains(uuid);
    }

    public void markTwofaPending(UUID uuid) {
        twofaPending.add(uuid);
    }

    public boolean isTwofaPending(UUID uuid) {
        return twofaPending.contains(uuid);
    }

    public void clearTwofaPending(UUID uuid) {
        twofaPending.remove(uuid);
    }

    public void markLoggedIn(UUID uuid, String ip, Instant now) {
        liveSessions.put(uuid, new Session(now, ip == null ? "" : ip));
        grace.remove(uuid);
        twofaPending.remove(uuid);
    }

    public void markLoggedOut(UUID uuid) {
        liveSessions.remove(uuid);
        grace.remove(uuid);
        twofaPending.remove(uuid);
    }

    public void recordQuit(UUID uuid, String ip, Instant now) {
        if (isLoggedIn(uuid)) {
            grace.put(uuid, new Grace(now, ip == null ? "" : ip));
        }
        twofaPending.remove(uuid);
    }

    public boolean canUseGrace(UUID uuid, String currentIp, Instant now) {
        Grace g = grace.get(uuid);
        if (g == null) return false;

        long graceSeconds = cfg.reconnectGraceSeconds();
        if (graceSeconds <= 0) return false;

        if (Duration.between(g.quitTime(), now).getSeconds() > graceSeconds) {
            grace.remove(uuid);
            return false;
        }

        return safeIpMatch(g.ip(), currentIp);
    }

    public void consumeGrace(UUID uuid, String currentIp, Instant now) {
        markLoggedIn(uuid, currentIp, now);
    }

    public void cleanupExpiredGrace() {
        Instant now = Instant.now();
        long graceSeconds = cfg.reconnectGraceSeconds();
        if (graceSeconds <= 0) {
            grace.clear();
            return;
        }

        for (var e : grace.entrySet()) {
            if (Duration.between(e.getValue().quitTime(), now).getSeconds() > graceSeconds) {
                grace.remove(e.getKey());
            }
        }
    }

    private boolean safeIpMatch(String a, String b) {
        return IpUtil.ipEquals(a, b);
    }

    private boolean isExpired(Instant authenticatedAt) {
        int hours = cfg.security().sessionExpiryHours();
        if (hours <= 0) return false;
        return Duration.between(authenticatedAt, Instant.now()).toHours() >= hours;
    }

    private record Session(Instant authenticatedAt, String ip) {}

    private record Grace(Instant quitTime, String ip) {}
}
