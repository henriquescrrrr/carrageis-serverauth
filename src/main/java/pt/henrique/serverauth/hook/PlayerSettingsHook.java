package pt.henrique.serverauth.hook;

import org.bukkit.Bukkit;
import org.bukkit.Material;

import java.lang.reflect.Method;
import java.util.UUID;
import java.util.logging.Logger;

/**
 * Reflection-based hook into the PlayerSettings plugin.
 * If PlayerSettings is present, queries the player's preferred language
 * and registers per-player preference toggles.
 * If absent, all methods return null / defaults gracefully.
 */
public class PlayerSettingsHook {

    private Object settingsProvider;
    private Method getLanguageMethod;
    private Method getBooleanMethod;
    private Method registerCategoryMethod;
    private Method registerToggleMethod;
    private Method unregisterAllMethod;
    private boolean available;

    public void init(Logger logger) {
        try {
            if (Bukkit.getPluginManager().getPlugin("PlayerSettings") == null) {
                available = false;
                return;
            }
            Class<?> apiClass = Class.forName("pt.henrique.playersettings.api.PlayerSettingsApi");
            var reg = Bukkit.getServicesManager().getRegistration(apiClass);
            if (reg != null && reg.getProvider() != null) {
                settingsProvider = reg.getProvider();
                getLanguageMethod = settingsProvider.getClass().getMethod("getLanguage", UUID.class);
                available = true;
                logger.info("PlayerSettings hook enabled — per-player language active.");

                // Preferences API methods (may not exist in older versions)
                try {
                    getBooleanMethod = settingsProvider.getClass().getMethod("getBoolean", UUID.class, String.class, boolean.class);
                    registerCategoryMethod = settingsProvider.getClass().getMethod("registerCategory",
                            String.class, Material.class, int.class);
                    registerToggleMethod = settingsProvider.getClass().getMethod("registerToggle",
                            String.class, String.class, boolean.class, Material.class, int.class);
                    unregisterAllMethod = settingsProvider.getClass().getMethod("unregisterAll", String.class);
                } catch (NoSuchMethodException e) {
                    logger.info("PlayerSettings preferences API not available — using defaults.");
                }
            } else {
                available = false;
            }
        } catch (Exception e) {
            available = false;
        }
    }

    /**
     * Registers ServerAUTH's per-player preference toggles with PlayerSettings.
     */
    public void registerSettings() {
        if (!available || registerCategoryMethod == null) return;
        try {
            registerCategoryMethod.invoke(settingsProvider, "serverauth", Material.IRON_DOOR, 70);
            registerToggleMethod.invoke(settingsProvider, "serverauth", "login-notifications", true, Material.BELL, 1);
        } catch (Exception ignored) {}
    }

    /**
     * Unregisters all ServerAUTH settings from PlayerSettings.
     */
    public void unregisterSettings() {
        if (!available || unregisterAllMethod == null) return;
        try {
            unregisterAllMethod.invoke(settingsProvider, "serverauth");
        } catch (Exception ignored) {}
    }

    /**
     * Returns the player's preferred language code (e.g. "pt_PT", "fr_FR"),
     * or null if PlayerSettings is not available or the player has no preference.
     */
    public String getLanguage(UUID uuid) {
        if (!available) return null;
        try {
            return (String) getLanguageMethod.invoke(settingsProvider, uuid);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Reads a boolean player setting with the given full key (e.g. "serverauth.login-notifications").
     * Returns defaultValue if PlayerSettings is unavailable or the key is not set.
     */
    public boolean getSetting(UUID uuid, String fullKey, boolean defaultValue) {
        if (!available || getBooleanMethod == null) return defaultValue;
        try {
            return (boolean) getBooleanMethod.invoke(settingsProvider, uuid, fullKey, defaultValue);
        } catch (Exception e) {
            return defaultValue;
        }
    }

    public boolean isAvailable() {
        return available;
    }
}

