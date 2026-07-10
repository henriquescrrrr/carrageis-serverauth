package pt.henrique.serverauth.commands;

import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import pt.henrique.serverauth.ServerAUTH;
import pt.henrique.serverauth.auth.AuthService;
import pt.henrique.serverauth.auth.TwoFactorService;
import pt.henrique.serverauth.i18n.MessageService;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * OP-only admin command for managing other players' auth data.
 * ALL sensitive operations require the admin's own 2FA code for verification.
 *
 * Subcommands:
 *   /authadmin lookup <player>                          - View player auth info
 *   /authadmin setpassword <player> <newpw> <2fa-code>  - Change a player's password
 *   /authadmin delete <player> <2fa-code>               - Delete a player's account
 *   /authadmin reset2fa <player> <2fa-code>             - Reset a player's 2FA
 *   /authadmin reload                                   - Reload config and language files
 */
public final class AuthAdminCommand extends BaseCommand {

    private final ServerAUTH plugin;
    private final AuthService auth;

    public AuthAdminCommand(ServerAUTH plugin, MessageService msg, AuthService auth, TwoFactorService twoFactor) {
        super(msg);
        this.plugin = plugin;
        this.auth = auth;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!sender.hasPermission("serverauth.admin")) {
            msg.send(sender, "errors.no-permission");
            return true;
        }

        if (args.length >= 1 && args[0].equalsIgnoreCase("reload")) {
            handleReload(sender);
            return true;
        }

        Player p = requirePlayer(sender);
        if (p == null) return true;


        if (!auth.isAuthenticated(p)) {
            msg.send(p, "errors.must-login");
            return true;
        }

        if (args.length < 1) {
            msg.send(p, "admin.usage");
            return true;
        }

        String sub = args[0].toLowerCase(Locale.ROOT);
        switch (sub) {
            case "lookup", "info", "view" -> handleLookup(p, args);
            case "setpassword", "setpw" -> handleSetPassword(p, args);
            case "delete", "unregister" -> handleDelete(p, args);
            case "reset2fa", "resettotp" -> handleReset2FA(p, args);
            default -> msg.send(p, "admin.usage");
        }
        return true;
    }

    private void handleReload(CommandSender sender) {
        plugin.performReload();
        msg.send(sender, "admin.reload-success");
    }

    private void handleLookup(Player p, String[] args) {
        if (args.length < 2) {
            msg.send(p, "admin.lookup-usage");
            return;
        }
        auth.adminLookup(p, args[1]);
    }

    private void handleSetPassword(Player p, String[] args) {
        // /authadmin setpassword <player> <newpw> <2fa-code>
        if (args.length < 4) {
            msg.send(p, "admin.setpassword-usage");
            return;
        }
        // Verify the admin has 2FA enabled first
        auth.load(p).thenAccept(opt -> {
            if (opt.isEmpty() || !opt.get().has2FA()) {
                p.getServer().getScheduler().runTask(plugin, () ->
                        msg.send(p, "admin.requires-2fa"));
                return;
            }
            auth.adminSetPassword(p, args[1], args[2], args[3]);
        });
    }

    private void handleDelete(Player p, String[] args) {
        // /authadmin delete <player> <2fa-code>
        if (args.length < 3) {
            msg.send(p, "admin.delete-usage");
            return;
        }
        auth.load(p).thenAccept(opt -> {
            if (opt.isEmpty() || !opt.get().has2FA()) {
                p.getServer().getScheduler().runTask(plugin, () ->
                        msg.send(p, "admin.requires-2fa"));
                return;
            }
            auth.adminDeleteAccount(p, args[1], args[2]);
        });
    }

    private void handleReset2FA(Player p, String[] args) {
        // /authadmin reset2fa <player> <2fa-code>
        if (args.length < 3) {
            msg.send(p, "admin.reset2fa-usage");
            return;
        }
        auth.load(p).thenAccept(opt -> {
            if (opt.isEmpty() || !opt.get().has2FA()) {
                p.getServer().getScheduler().runTask(plugin, () ->
                        msg.send(p, "admin.requires-2fa"));
                return;
            }
            auth.adminReset2FA(p, args[1], args[2]);
        });
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
        if (!sender.hasPermission("serverauth.admin")) return List.of();

        if (args.length == 1) {
            return List.of("lookup", "setpassword", "delete", "reset2fa", "reload");
        }
        if (args.length == 2) {
            // Suggest online player names
            String prefix = args[1].toLowerCase(Locale.ROOT);
            List<String> names = new ArrayList<>();
            for (Player p : Bukkit.getOnlinePlayers()) {
                if (p.getName().toLowerCase(Locale.ROOT).startsWith(prefix)) {
                    names.add(p.getName());
                }
            }
            return names;
        }
        return List.of();
    }
}




