package pt.henrique.serverauth.commands;

import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import pt.henrique.serverauth.auth.AuthService;
import pt.henrique.serverauth.config.PluginConfig;
import pt.henrique.serverauth.i18n.MessageService;

public final class ChangePasswordCommand extends BaseCommand {

    private final PluginConfig cfg;
    private final AuthService auth;

    public ChangePasswordCommand(PluginConfig cfg, MessageService msg, AuthService auth) {
        super(msg);
        this.cfg = cfg;
        this.auth = auth;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!requirePerm(sender)) return true;
        Player p = requirePlayer(sender);
        if (p == null) return true;

        if (args.length < 3) {
            msg.send(p, "changepassword.usage");
            return true;
        }

        if (!auth.isAuthenticated(p)) {
            msg.send(p, "errors.must-login");
            return true;
        }

        auth.changePassword(p, args[0], args[1], args[2]);
        return true;
    }
}

