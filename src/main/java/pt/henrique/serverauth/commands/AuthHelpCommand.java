package pt.henrique.serverauth.commands;

import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import pt.henrique.serverauth.auth.AuthService;
import pt.henrique.serverauth.config.PluginConfig;
import pt.henrique.serverauth.i18n.MessageService;

public final class AuthHelpCommand extends BaseCommand {

    private final PluginConfig cfg;
    private final AuthService auth;

    public AuthHelpCommand(PluginConfig cfg, MessageService msg, AuthService auth) {
        super(msg);
        this.cfg = cfg;
        this.auth = auth;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!requirePerm(sender)) return true;
        Player p = requirePlayer(sender);
        if (p == null) return true;

        msg.send(p, "help.title");
        // Help state uses sync DB call; small but ok. Could be improved later.
        AuthService.AuthHelpState state = auth.helpState(p);
        switch (state) {
            case UNREGISTERED -> msg.sendList(p, "help.unregistered", java.util.Map.of());
            case LOCKED -> msg.sendList(p, "help.locked", java.util.Map.of());
            case TWO_FA_PENDING -> msg.sendList(p, "help.twofa-pending", java.util.Map.of());
            case LOGGED_IN -> msg.sendList(p, "help.logged", java.util.Map.of());
        }
        return true;
    }
}
