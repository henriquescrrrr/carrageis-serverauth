package pt.henrique.serverauth.auth;

import org.bukkit.Bukkit;
import org.bukkit.entity.Player;

import java.lang.reflect.Method;
import java.util.UUID;

/**
 * Thin, fail-safe bridge to the Floodgate API. Floodgate is a soft-dependency,
 * so this is done purely by reflection — there is no compile-time dependency on
 * Floodgate and no bundled jar. If Floodgate (or the API class) isn't present,
 * everything degrades to "not a Bedrock player" and ServerAUTH behaves exactly
 * as before. The reflected handles are resolved once and cached.
 */
public final class FloodgateBridge {

    private FloodgateBridge() {
    }

    private static Boolean pluginPresent;
    private static volatile boolean resolved;
    private static Object apiInstance;          // FloodgateApi singleton
    private static Method isFloodgatePlayer;    // boolean isFloodgatePlayer(UUID)

    /** Whether the Floodgate plugin is installed + enabled. Cached after first call. */
    public static boolean isAvailable() {
        if (pluginPresent == null) {
            pluginPresent = Bukkit.getPluginManager().getPlugin("floodgate") != null;
        }
        return pluginPresent;
    }

    private static void resolve() {
        if (resolved) {
            return;
        }
        resolved = true;
        try {
            Class<?> apiClass = Class.forName("org.geysermc.floodgate.api.FloodgateApi");
            apiInstance = apiClass.getMethod("getInstance").invoke(null);
            isFloodgatePlayer = apiClass.getMethod("isFloodgatePlayer", UUID.class);
        } catch (Throwable t) {
            apiInstance = null;
            isFloodgatePlayer = null;
        }
    }

    /**
     * True only for a player whose identity Floodgate verified via Xbox Live
     * (a Bedrock/crossplay player). False for Java players, and false (never
     * throws) when Floodgate is absent or the API can't be reached.
     */
    public static boolean isBedrockPlayer(Player p) {
        if (p == null || !isAvailable()) {
            return false;
        }
        resolve();
        if (apiInstance == null || isFloodgatePlayer == null) {
            return false;
        }
        try {
            return (Boolean) isFloodgatePlayer.invoke(apiInstance, p.getUniqueId());
        } catch (Throwable t) {
            return false;
        }
    }
}
