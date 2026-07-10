package pt.henrique.serverauth.auth;

import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;
import pt.henrique.serverauth.config.PluginConfig;
import pt.henrique.serverauth.i18n.MessageService;

public final class TitleReminderService {

    private final Plugin plugin;
    private final PluginConfig cfg;
    private final MessageService msg;
    private final AuthService auth;

    public TitleReminderService(Plugin plugin, PluginConfig cfg, MessageService msg, AuthService auth) {
        this.plugin = plugin;
        this.cfg = cfg;
        this.msg = msg;
        this.auth = auth;
    }

    public void start() {
        int seconds = cfg.titleReminderIntervalSeconds();
        if (seconds <= 0) return;

        long period = Math.max(20L, seconds * 20L);
        Bukkit.getScheduler().runTaskTimer(plugin, this::tick, period, period);
    }

    private void tick() {
        for (Player p : Bukkit.getOnlinePlayers()) {
            if (auth.isAuthenticated(p)) continue;

            // 2FA pending: show 2FA title
            if (auth.isTwofaPending(p)) {
                sendTitle(p,
                        msg.raw(p, "auth.title.twofa"),
                        msg.raw(p, "auth.title.twofa-sub"));
                continue;
            }

            auth.load(p).thenAccept(opt -> Bukkit.getScheduler().runTask(plugin, () -> {
                if (!p.isOnline() || auth.isAuthenticated(p) || auth.isTwofaPending(p)) return;

                if (opt.isEmpty()) {
                    sendTitle(p,
                            msg.raw(p, "auth.title.register"),
                            msg.raw(p, "auth.title.register-sub"));
                } else {
                    sendTitle(p,
                            msg.raw(p, "auth.title.login"),
                            msg.raw(p, "auth.title.login-sub"));
                }
            }));
        }
    }

    private void sendTitle(Player p, String title, String subtitle) {
        // fadeIn, stay, fadeOut in ticks
        p.sendTitle(title, subtitle, 5, 40, 10);
    }
}
