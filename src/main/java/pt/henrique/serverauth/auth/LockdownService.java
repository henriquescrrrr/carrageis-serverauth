package pt.henrique.serverauth.auth;

import org.bukkit.Bukkit;
import org.bukkit.Location;
import org.bukkit.entity.Player;
import org.bukkit.potion.PotionEffect;
import org.bukkit.potion.PotionEffectType;
import pt.henrique.serverauth.config.PluginConfig;
import pt.henrique.serverauth.i18n.MessageService;
import pt.henrique.serverauth.storage.UserRepository;
import pt.henrique.serverauth.util.Async;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public final class LockdownService {

    private final PluginConfig cfg;
    private final MessageService msg;
    private final AuthService auth;
    private final UserRepository repo;
    private final Async async;

    private final Set<UUID> tracked = Collections.newSetFromMap(new WeakHashMap<>());

    /**
     * In-memory cache of the player's REAL location captured on join,
     * BEFORE we teleport them to the login spawn.
     * Also persisted to DB so it survives a server restart.
     */
    private final Map<UUID, Location> savedLocations = new ConcurrentHashMap<>();

    public LockdownService(PluginConfig cfg, MessageService msg, AuthService auth,
                           UserRepository repo, Async async) {
        this.cfg = cfg;
        this.msg = msg;
        this.auth = auth;
        this.repo = repo;
        this.async = async;
    }

    /** Locked = not fully authenticated (includes 2FA-pending players). */
    public boolean isLocked(Player p) {
        if (!cfg.lockdown().enabled()) return false;
        return !auth.isAuthenticated(p);
    }

    public boolean isCommandAllowed(String message) {
        String cmd = message.trim();
        if (cmd.startsWith("/")) cmd = cmd.substring(1);
        if (cmd.isBlank()) return false;
        String base = cmd.split("\\s+")[0].toLowerCase(Locale.ROOT);
        return cfg.lockdown().allowedNormalized().contains(base);
    }

    public void track(Player p) {
        tracked.add(p.getUniqueId());

        // track() is called from PlayerJoinEvent and again from AuthService.handleJoin
        // when the session is dropped on an IP change — both in the same tick. A second
        // capture would read the login spawn as the "real" location and could win the
        // race against the first call's async write, stranding the player there.
        if (savedLocations.containsKey(p.getUniqueId())) {
            applyDarkness(p);
            return;
        }

        if (cfg.lockdown().hideCoordinatesDuringLogin()) {
            // Capture the real location BEFORE any teleport.
            // The server has placed the player where they logged out.
            Location real = p.getLocation().clone();
            savedLocations.put(p.getUniqueId(), real);

            // Persist to DB so it survives a server restart.
            // BUT only if the DB doesn't already have a saved location,
            // because after a restart the player spawns at the login spawn (0,0,0)
            // and we don't want to overwrite the real location from before the restart.
            String locStr = locationToString(real);
            String lower = p.getName().toLowerCase(Locale.ROOT);
            async.run(() -> {
                repo.findByUsernameLower(lower).ifPresent(u -> {
                    if (u.lastLogoutLocation() == null || u.lastLogoutLocation().isBlank()) {
                        repo.updateLastLogoutLocation(u.id(), locStr, Instant.now());
                    } else {
                        // DB already has a saved location (from before a restart).
                        // Keep it — it's the real one.
                    }
                });
            });

            Location loginSpawn = parseSpawn(cfg.lockdown().loginSpawnLocation());
            if (loginSpawn != null) {
                p.teleport(loginSpawn);
            }
        } else if (cfg.lockdown().teleportToAuthSpawn()) {
            Location loc = parseSpawn(cfg.lockdown().spawnLocation());
            if (loc != null) {
                p.teleport(loc);
            }
        }

        applyDarkness(p);
    }

    /**
     * Called when a player becomes fully authenticated.
     * Removes lockdown effects and teleports them back to their real location.
     *
     * Priority: DB location (survives restarts) > in-memory location.
     * If the DB has a saved location, it means the player was mid-login when the
     * server last wrote it — always prefer that. Otherwise fall back to in-memory.
     */
    public void restoreAndUntrack(Player p) {
        tracked.remove(p.getUniqueId());
        p.removePotionEffect(PotionEffectType.DARKNESS);

        if (!cfg.lockdown().hideCoordinatesDuringLogin()) return;

        // Grab in-memory value (might be the login-spawn after a restart)
        Location memoryLoc = savedLocations.remove(p.getUniqueId());

        // Check DB for the authoritative real location
        String lower = p.getName().toLowerCase(Locale.ROOT);
        async.supply(() -> repo.findByUsernameLower(lower)).thenAccept(opt -> {
            if (opt.isEmpty()) {
                // No DB record — use memory if available
                if (memoryLoc != null) {
                    async.sync(() -> { if (p.isOnline()) p.teleport(memoryLoc); });
                }
                return;
            }

            String dbLocStr = opt.get().lastLogoutLocation();
            Location dbLoc = parseSpawn(dbLocStr);

            // Clear DB now that we're restoring
            repo.updateLastLogoutLocation(opt.get().id(), null, Instant.now());

            if (dbLoc != null) {
                // DB has the real location — use it (handles restart case)
                async.sync(() -> { if (p.isOnline()) p.teleport(dbLoc); });
            } else if (memoryLoc != null) {
                // DB was empty — use in-memory (normal case, first login after feature enabled)
                async.sync(() -> { if (p.isOnline()) p.teleport(memoryLoc); });
            }
        });
    }

    public void untrack(Player p) {
        tracked.remove(p.getUniqueId());
        savedLocations.remove(p.getUniqueId());
        p.removePotionEffect(PotionEffectType.DARKNESS);
    }

    public void refreshDarknessForUnauthenticated() {
        for (UUID uuid : new ArrayList<>(tracked)) {
            Player p = Bukkit.getPlayer(uuid);
            if (p == null || !p.isOnline()) continue;
            if (!isLocked(p)) {
                restoreAndUntrack(p);
                continue;
            }
            applyDarkness(p);
        }
    }

    public void deny(Player p) {
        msg.send(p, "errors.must-login");
    }

    private void applyDarkness(Player p) {
        if (!cfg.lockdown().applyDarkness()) return;
        PotionEffect eff = new PotionEffect(PotionEffectType.DARKNESS, 60, 0, true, false, false);
        p.addPotionEffect(eff);
    }

    private static String locationToString(Location loc) {
        if (loc == null || loc.getWorld() == null) return null;
        return loc.getWorld().getName() + "," + loc.getX() + "," + loc.getY() + "," + loc.getZ() + "," + loc.getYaw() + "," + loc.getPitch();
    }

    private Location parseSpawn(String raw) {
        try {
            if (raw == null || raw.isBlank()) return null;
            String[] parts = raw.split(",");
            if (parts.length < 6) return null;
            var world = Bukkit.getWorld(parts[0]);
            if (world == null) return null;
            double x = Double.parseDouble(parts[1]);
            double y = Double.parseDouble(parts[2]);
            double z = Double.parseDouble(parts[3]);
            float yaw = Float.parseFloat(parts[4]);
            float pitch = Float.parseFloat(parts[5]);
            return new Location(world, x, y, z, yaw, pitch);
        } catch (Exception ignored) {
            return null;
        }
    }
}
