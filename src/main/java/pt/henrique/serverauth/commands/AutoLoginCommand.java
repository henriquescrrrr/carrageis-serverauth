package pt.henrique.serverauth.commands;

import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import pt.henrique.serverauth.auth.AuthService;
import pt.henrique.serverauth.config.PluginConfig;
import pt.henrique.serverauth.i18n.MessageService;

import java.util.List;

public final class AutoLoginCommand extends BaseCommand {

    private final PluginConfig cfg;
    private final AuthService auth;

    public AutoLoginCommand(PluginConfig cfg, MessageService msg, AuthService auth) {
        super(msg);
        this.cfg = cfg;
        this.auth = auth;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!requirePerm(sender)) return true;
        Player p = requirePlayer(sender);
        if (p == null) return true;

        if (args.length < 1) {
            msg.send(p, "autologin.usage");
            return true;
        }

        String sub = args[0].toLowerCase();
        switch (sub) {
            case "on" -> auth.setAutologin(p, true);
            case "off" -> auth.setAutologin(p, false);
            case "status" -> auth.autologinStatus(p);
            default -> msg.send(p, "autologin.usage");
        }
        return true;
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
        if (args.length == 1) return List.of("on", "off", "status");
        return List.of();
    }
}

