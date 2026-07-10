package pt.henrique.serverauth.commands;

import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;
import pt.henrique.serverauth.auth.AuthService;
import pt.henrique.serverauth.auth.TwoFactorService;
import pt.henrique.serverauth.config.PluginConfig;
import pt.henrique.serverauth.i18n.MessageService;

import java.util.List;
import java.util.Map;

public final class TwoFactorCommand extends BaseCommand {

    private final Plugin plugin;
    private final PluginConfig cfg;
    private final AuthService auth;
    private final TwoFactorService twoFactor;

    public TwoFactorCommand(Plugin plugin, PluginConfig cfg, MessageService msg, AuthService auth, TwoFactorService twoFactor) {
        super(msg);
        this.plugin = plugin;
        this.cfg = cfg;
        this.auth = auth;
        this.twoFactor = twoFactor;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!requirePerm(sender)) return true;
        Player p = requirePlayer(sender);
        if (p == null) return true;

        if (!cfg.twoFactor().enabled()) {
            msg.send(p, "2fa.disabled-by-server");
            return true;
        }

        if (args.length < 1) {
            msg.send(p, "2fa.usage");
            return true;
        }

        String sub = args[0].toLowerCase();
        switch (sub) {
            case "setup" -> handleSetup(p);
            case "confirm" -> handleConfirm(p, args);
            case "code", "verify" -> handleVerify(p, args);
            case "disable" -> handleDisable(p, args);
            case "status" -> handleStatus(p);
            default -> msg.send(p, "2fa.usage");
        }
        return true;
    }

    private void handleSetup(Player p) {
        // Must be password-authenticated or 2FA-pending (ops who need to set up)
        if (!auth.isAuthenticated(p) && !auth.isTwofaPending(p)) {
            msg.send(p, "errors.must-login");
            return;
        }

        auth.load(p).thenAccept(opt -> {
            if (opt.isPresent() && opt.get().has2FA()) {
                plugin.getServer().getScheduler().runTask(plugin, () -> msg.send(p, "2fa.already-enabled"));
                return;
            }
            plugin.getServer().getScheduler().runTask(plugin, () -> {
                String webToken = twoFactor.createSetupToken(p.getUniqueId(), p.getName());

                if (cfg.web().enabled()) {
                    // Send a single clickable link — entire setup happens in browser
                    String url = cfg.web().publicUrl() + "/setup?token=" + webToken;
                    msg.sendClickableLink(p, "2fa.setup-link", url, Map.of("url", url));
                } else {
                    // No web server: fallback to manual secret + in-game confirm
                    var token = twoFactor.getSetupToken(p.getUniqueId());
                    if (token != null) {
                        String uri = twoFactor.buildOtpAuthUri(token.secret(), p.getName());
                        msg.send(p, "2fa.setup-manual", Map.of("secret", token.secret()));
                        msg.send(p, "2fa.setup-uri", Map.of("uri", uri));
                    }
                    msg.send(p, "2fa.setup-confirm-hint");
                }
            });
        });
    }

    /** CLI confirm — only used when web server is disabled (fallback). */
    private void handleConfirm(Player p, String[] args) {
        if (!cfg.web().enabled()) {
            // CLI fallback
            if (!auth.isAuthenticated(p) && !auth.isTwofaPending(p)) {
                msg.send(p, "errors.must-login");
                return;
            }
            if (args.length < 2) {
                msg.send(p, "2fa.confirm-usage");
                return;
            }
            try {
                int code = Integer.parseInt(args[1].trim());
                twoFactor.confirmSetupCli(p, code);
            } catch (NumberFormatException e) {
                msg.send(p, "2fa.invalid-code");
            }
        } else {
            // Web server is enabled — setup is done entirely in browser
            msg.send(p, "2fa.setup-use-browser");
        }
    }

    private void handleVerify(Player p, String[] args) {
        if (!auth.isTwofaPending(p)) {
            msg.send(p, "2fa.not-pending");
            return;
        }
        if (args.length < 2) {
            msg.send(p, "2fa.verify-usage");
            return;
        }
        twoFactor.verify(p, args[1]);
    }

    private void handleDisable(Player p, String[] args) {
        if (!auth.isAuthenticated(p)) {
            msg.send(p, "errors.must-login");
            return;
        }
        if (args.length < 2) {
            msg.send(p, "2fa.disable-usage");
            return;
        }
        twoFactor.disable(p, args[1]);
    }

    private void handleStatus(Player p) {
        if (!auth.isPasswordAuthenticated(p) && !auth.isTwofaPending(p)) {
            msg.send(p, "errors.must-login");
            return;
        }
        auth.load(p).thenAccept(opt ->
            plugin.getServer().getScheduler().runTask(plugin, () -> {
                if (opt.isPresent() && opt.get().has2FA()) {
                    msg.send(p, "2fa.status-enabled");
                } else {
                    msg.send(p, "2fa.status-disabled");
                }
            })
        );
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
        if (args.length == 1) return List.of("setup", "confirm", "code", "verify", "disable", "status");
        return List.of();
    }
}
