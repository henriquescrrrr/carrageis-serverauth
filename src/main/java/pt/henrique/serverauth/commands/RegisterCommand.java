package pt.henrique.serverauth.commands;

import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import pt.henrique.serverauth.auth.AuthService;
import pt.henrique.serverauth.config.PluginConfig;
import pt.henrique.serverauth.i18n.MessageService;

public final class RegisterCommand extends BaseCommand {

    private final PluginConfig cfg;
    private final AuthService auth;

    public RegisterCommand(PluginConfig cfg, MessageService msg, AuthService auth) {
        super(msg);
        this.cfg = cfg;
        this.auth = auth;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!requirePerm(sender)) return true;
        Player p = requirePlayer(sender);
        if (p == null) return true;

        if (args.length < 2) {
            msg.send(p, "register.usage");
            return true;
        }

        auth.register(p, args[0], args[1]);
        return true;
    }
}

