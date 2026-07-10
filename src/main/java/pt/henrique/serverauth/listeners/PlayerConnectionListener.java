package pt.henrique.serverauth.listeners;

import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import pt.henrique.serverauth.ServerAUTH;
import pt.henrique.serverauth.auth.AuthService;
import pt.henrique.serverauth.auth.FloodgateBridge;
import pt.henrique.serverauth.auth.LockdownService;
import pt.henrique.serverauth.config.PluginConfig;
import pt.henrique.serverauth.i18n.MessageService;

public final class PlayerConnectionListener implements Listener {

    private final ServerAUTH plugin;
    private final PluginConfig cfg;
    private final MessageService msg;
    private final AuthService auth;
    private final LockdownService lockdown;

    public PlayerConnectionListener(ServerAUTH plugin, PluginConfig cfg, MessageService msg, AuthService auth, LockdownService lockdown) {
        this.plugin = plugin;
        this.cfg = cfg;
        this.msg = msg;
        this.auth = auth;
        this.lockdown = lockdown;
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onJoin(PlayerJoinEvent e) {
        Player p = e.getPlayer();

        if (cfg.lockdown().enabled()) {
            lockdown.track(p);
        }

        auth.handleJoin(p);

        // One-time chat reminder on join
        auth.load(p).thenAccept(opt -> plugin.getServer().getScheduler().runTask(plugin, () -> {
            if (!p.isOnline()) return;

            // If fully authenticated (e.g. grace/autologin), nothing to show
            if (auth.isAuthenticated(p)) return;

            // Bedrock players are auto-logged-in by Floodgate (async) — no prompt.
            if (cfg.floodgate().autoLogin() && FloodgateBridge.isBedrockPlayer(p)) return;

            // If 2FA pending, show 2FA prompt
            if (auth.isTwofaPending(p)) {
                msg.send(p, "2fa.verify-prompt");
                return;
            }

            if (opt.isEmpty()) {
                msg.send(p, "register.usage");
                return;
            }

            msg.send(p, "login.usage");

            if (cfg.remindRecoveryOnJoin() && !opt.get().hasRecovery()) {
                msg.send(p, "recovery-recommend.line1");
                msg.send(p, "recovery-recommend.line2");
            }
        }));
    }

    @EventHandler
    public void onQuit(PlayerQuitEvent e) {
        auth.handleQuit(e.getPlayer());
    }
}
