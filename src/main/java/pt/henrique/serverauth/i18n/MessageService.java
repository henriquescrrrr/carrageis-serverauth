package pt.henrique.serverauth.i18n;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.event.ClickEvent;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import org.bukkit.command.CommandSender;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.plugin.java.JavaPlugin;
import pt.henrique.serverauth.hook.PlayerSettingsHook;

import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Handles localised messages. Loads ALL .yml files from the lang/ folder into
 * a per-locale map. When sending a message to a {@link Player}, the service:
 * <ol>
 *     <li>Queries {@link PlayerSettingsHook} for the player's preferred language</li>
 *     <li>Falls back to the global {@code language} setting from config.yml</li>
 *     <li>Falls back to {@code en_US} if the key is missing in the resolved locale</li>
 * </ol>
 */
public final class MessageService {

    private static final LegacyComponentSerializer LEGACY =
            LegacyComponentSerializer.legacyAmpersand();

    private static final String FALLBACK_LOCALE = "en_US";

    /** Bundled locale files shipped inside the JAR. */
    private static final String[] BUNDLED_LOCALES = {"en_US", "pt_PT", "fr_FR"};

    private final JavaPlugin plugin;
    private final String defaultLocale;

    /** locale → loaded YamlConfiguration */
    private final Map<String, YamlConfiguration> locales = new ConcurrentHashMap<>();

    private PlayerSettingsHook settingsHook;

    public MessageService(JavaPlugin plugin, String defaultLocale) {
        this.plugin = plugin;
        this.defaultLocale = defaultLocale == null ? FALLBACK_LOCALE : defaultLocale;
    }

    // ---- Hook wiring ----

    public void setPlayerSettingsHook(PlayerSettingsHook hook) {
        this.settingsHook = hook;
    }

    // ---- Reload ----

    /**
     * (Re)loads every locale. First loads bundled resources, then overrides with
     * files found in the plugin's {@code lang/} data folder.
     */
    public void reload() {
        locales.clear();

        // 1. Load bundled resources from JAR
        for (String locale : BUNDLED_LOCALES) {
            loadFromResource(locale);
        }

        // 2. Override / add from data folder  (lang/*.yml)
        File langDir = new File(plugin.getDataFolder(), "lang");
        if (langDir.isDirectory()) {
            File[] files = langDir.listFiles((dir, name) -> name.endsWith(".yml"));
            if (files != null) {
                for (File f : files) {
                    String locale = f.getName().replace(".yml", "");
                    try {
                        YamlConfiguration cfg = YamlConfiguration.loadConfiguration(f);
                        locales.put(locale, cfg);
                    } catch (Exception e) {
                        plugin.getLogger().warning("Failed to load lang file " + f.getName() + ": " + e.getMessage());
                    }
                }
            }
        }

        // Make sure at least the fallback exists
        if (!locales.containsKey(FALLBACK_LOCALE)) {
            locales.put(FALLBACK_LOCALE, new YamlConfiguration());
        }
    }

    private void loadFromResource(String locale) {
        String path = "lang/" + locale + ".yml";
        try {
            var res = plugin.getResource(path);
            if (res == null) return;
            YamlConfiguration cfg = YamlConfiguration.loadConfiguration(
                    new InputStreamReader(res, StandardCharsets.UTF_8));
            locales.put(locale, cfg);
        } catch (Exception e) {
            plugin.getLogger().warning("Failed to load bundled lang " + locale + ": " + e.getMessage());
        }
    }

    // ---- Locale resolution ----

    /**
     * Resolve the locale for a given sender.
     * Player → PlayerSettings language → global default → en_US
     * Console → global default → en_US
     */
    private String resolveLocale(CommandSender sender) {
        if (sender instanceof Player player && settingsHook != null && settingsHook.isAvailable()) {
            String lang = settingsHook.getLanguage(player.getUniqueId());
            if (lang != null && !lang.isBlank() && locales.containsKey(lang)) {
                return lang;
            }
        }
        return locales.containsKey(defaultLocale) ? defaultLocale : FALLBACK_LOCALE;
    }

    // ---- Send helpers ----

    public void send(CommandSender sender, String key) {
        send(sender, key, Map.of());
    }

    public void send(CommandSender sender, String key, Map<String, String> placeholders) {
        String raw = getRaw(sender, key);
        if (raw == null) return;
        String resolved = placeholders(applyPrefix(sender, raw), placeholders);
        sender.sendMessage(LEGACY.deserialize(resolved));
    }

    /**
     * Send a message that contains a clickable URL. The {url} placeholder in the
     * message will be rendered as an actual clickable link in chat.
     */
    public void sendClickableLink(Player player, String key, String url, Map<String, String> placeholders) {
        String raw = getRaw(player, key);
        if (raw == null) return;
        String resolved = placeholders(applyPrefix(player, raw), placeholders);

        String placeholder = "{url}";
        int idx = resolved.indexOf(placeholder);
        if (idx < 0) {
            player.sendMessage(LEGACY.deserialize(resolved)
                    .append(Component.text(" "))
                    .append(Component.text(url)
                            .clickEvent(ClickEvent.openUrl(url))
                            .color(net.kyori.adventure.text.format.NamedTextColor.AQUA)
                            .decorate(net.kyori.adventure.text.format.TextDecoration.UNDERLINED)));
            return;
        }

        String before = resolved.substring(0, idx);
        String after = resolved.substring(idx + placeholder.length());

        Component link = Component.text(url)
                .clickEvent(ClickEvent.openUrl(url))
                .color(net.kyori.adventure.text.format.NamedTextColor.AQUA)
                .decorate(net.kyori.adventure.text.format.TextDecoration.UNDERLINED);

        Component msg = LEGACY.deserialize(before)
                .append(link)
                .append(LEGACY.deserialize(after));

        player.sendMessage(msg);
    }

    public void sendList(CommandSender sender, String key, Map<String, String> placeholders) {
        YamlConfiguration cfg = resolveConfig(sender);
        Object val = cfg.get(key);

        // If not found in the player's locale, try fallback
        if (val == null) {
            cfg = locales.getOrDefault(FALLBACK_LOCALE, new YamlConfiguration());
            val = cfg.get(key);
        }

        if (val instanceof List<?> list) {
            for (Object o : list) {
                if (o == null) continue;
                String line = String.valueOf(o);
                String resolved = placeholders(applyPrefix(sender, line), placeholders);
                sender.sendMessage(LEGACY.deserialize(resolved));
            }
            return;
        }
        // Fall back to single-line send
        send(sender, key, placeholders);
    }

    public String raw(CommandSender sender, String key) {
        String s = getRaw(sender, key);
        return s == null ? "" : color(applyPrefix(sender, s));
    }

    /**
     * Convenience overload for places that don't have a sender context (e.g. titles).
     * Uses the global default locale.
     */
    public String raw(String key) {
        YamlConfiguration cfg = locales.getOrDefault(defaultLocale,
                locales.getOrDefault(FALLBACK_LOCALE, new YamlConfiguration()));
        String s = cfg.getString(key);
        if (s == null) {
            cfg = locales.getOrDefault(FALLBACK_LOCALE, new YamlConfiguration());
            s = cfg.getString(key);
        }
        if (s == null) return "";
        String prefix = cfg.getString("prefix", "");
        return color(s.replace("{prefix}", prefix));
    }

    // ---- Internals ----

    private String getRaw(CommandSender sender, String key) {
        YamlConfiguration cfg = resolveConfig(sender);
        String val = cfg.getString(key);
        if (val != null) return val;

        // Fallback to en_US
        YamlConfiguration fallback = locales.getOrDefault(FALLBACK_LOCALE, new YamlConfiguration());
        return fallback.getString(key);
    }

    private YamlConfiguration resolveConfig(CommandSender sender) {
        String locale = resolveLocale(sender);
        return locales.getOrDefault(locale,
                locales.getOrDefault(FALLBACK_LOCALE, new YamlConfiguration()));
    }

    private String applyPrefix(CommandSender sender, String s) {
        YamlConfiguration cfg = resolveConfig(sender);
        String prefix = cfg.getString("prefix", "");
        return s.replace("{prefix}", prefix);
    }

    private static String placeholders(String s, Map<String, String> placeholders) {
        String out = s;
        for (var e : placeholders.entrySet()) {
            out = out.replace("{" + e.getKey() + "}", e.getValue());
        }
        return out;
    }

    @SuppressWarnings("deprecation")
    private static String color(String s) {
        return org.bukkit.ChatColor.translateAlternateColorCodes('&', s);
    }
}
