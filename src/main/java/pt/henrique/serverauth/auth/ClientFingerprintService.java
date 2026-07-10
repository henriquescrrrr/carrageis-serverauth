package pt.henrique.serverauth.auth;

import com.destroystokyo.paper.event.player.PlayerClientOptionsChangeEvent;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.plugin.messaging.PluginMessageListener;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Captures and stores client fingerprint data for each player:
 * - Client brand (vanilla, fabric, forge, lunarclient, etc.) via plugin message on "minecraft:brand"
 * - Client settings hash (locale, view distance, chat visibility, skin parts, main hand)
 *   via Paper's PlayerClientOptionsChangeEvent
 *
 * The combined fingerprint is "brand:settingsHash" and is used as one layer
 * of auto-login verification.
 */
public class ClientFingerprintService implements Listener, PluginMessageListener {

    private final Map<UUID, String> pendingBrands = new ConcurrentHashMap<>();
    private final Map<UUID, String> pendingSettingsHashes = new ConcurrentHashMap<>();

    // ---- Plugin message: client brand ----

    /**
     * Called when a plugin message is received on the "minecraft:brand" channel.
     * The payload is a length-prefixed UTF-8 string.
     */
    @Override
    public void onPluginMessageReceived(String channel, Player player, byte[] message) {
        if (!"minecraft:brand".equals(channel)) return;
        try {
            String brand;
            if (message.length > 1) {
                int length = message[0] & 0xFF;
                if (length > 0 && length < message.length) {
                    brand = new String(message, 1, Math.min(length, message.length - 1), StandardCharsets.UTF_8);
                } else {
                    brand = new String(message, StandardCharsets.UTF_8).trim();
                }
            } else {
                brand = "unknown";
            }
            // Strip control characters: the brand is fully client-controlled and ends up
            // in the security/console logs; unsanitised newlines would allow log forging.
            brand = brand.toLowerCase().trim().replaceAll("\\p{Cntrl}", "");
            if (brand.length() > 128) brand = brand.substring(0, 128);
            pendingBrands.put(player.getUniqueId(), brand);
        } catch (Exception e) {
            pendingBrands.put(player.getUniqueId(), "error");
        }
    }

    // ---- Paper event: client settings ----

    @EventHandler
    public void onClientOptions(PlayerClientOptionsChangeEvent event) {
        captureSettings(event.getPlayer(),
                event.getLocale(),
                event.getViewDistance(),
                event.getChatVisibility().name(),
                event.getSkinParts().getRaw(),
                event.getMainHand().name());
    }

    /**
     * Capture client settings and compute a short hash.
     */
    public void captureSettings(Player player, String locale, int viewDistance,
                                String chatVisibility, int skinParts, String mainHand) {
        String raw = locale + "|" + viewDistance + "|" + chatVisibility + "|" + skinParts + "|" + mainHand;
        String hash = sha256Short(raw);
        pendingSettingsHashes.put(player.getUniqueId(), hash);
    }

    // ---- Fingerprint access ----

    /**
     * Build the full fingerprint string: "brand:settingsHash".
     */
    public String getFingerprint(UUID uuid) {
        String brand = pendingBrands.getOrDefault(uuid, "unknown");
        String settings = pendingSettingsHashes.getOrDefault(uuid, "unknown");
        return brand + ":" + settings;
    }

    public String getBrand(UUID uuid) {
        return pendingBrands.getOrDefault(uuid, "unknown");
    }

    public String getSettingsHash(UUID uuid) {
        return pendingSettingsHashes.getOrDefault(uuid, "unknown");
    }

    /**
     * Check if a fingerprint matches the stored one.
     * Returns true if:
     * - Stored fingerprint is null/empty (first login, not yet captured)
     * - Brand matches AND settings hash matches
     *
     * Returns false if both stored and current are available but don't match.
     * "unknown" is treated as a wildcard (data not captured yet).
     */
    public boolean fingerprintMatches(String storedFingerprint, String currentFingerprint) {
        if (storedFingerprint == null || storedFingerprint.isEmpty()) return true;
        if (currentFingerprint == null) return true;

        String[] stored = storedFingerprint.split(":", 2);
        String[] current = currentFingerprint.split(":", 2);

        String storedBrand = stored.length > 0 ? stored[0] : "unknown";
        String currentBrand = current.length > 0 ? current[0] : "unknown";

        // Brand must match (case-insensitive). "unknown" matches anything.
        if (!"unknown".equals(storedBrand) && !"unknown".equals(currentBrand)) {
            if (!storedBrand.equalsIgnoreCase(currentBrand)) {
                return false;
            }
        }

        // Settings hash comparison
        String storedHash = stored.length > 1 ? stored[1] : "unknown";
        String currentHash = current.length > 1 ? current[1] : "unknown";
        if (!"unknown".equals(storedHash) && !"unknown".equals(currentHash)) {
            if (!storedHash.equalsIgnoreCase(currentHash)) {
                return false;
            }
        }

        return true;
    }

    // ---- Cleanup ----

    @EventHandler
    public void onQuit(PlayerQuitEvent event) {
        UUID uuid = event.getPlayer().getUniqueId();
        pendingBrands.remove(uuid);
        pendingSettingsHashes.remove(uuid);
    }

    // ---- Internal ----

    /**
     * First 16 hex chars (8 bytes) of SHA-256.
     */
    private String sha256Short(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 8; i++) {
                sb.append(String.format("%02x", hash[i]));
            }
            return sb.toString();
        } catch (Exception e) {
            return "error";
        }
    }
}

