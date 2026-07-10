package pt.henrique.serverauth.commands;

import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;
import org.bukkit.entity.Player;
import pt.henrique.serverauth.i18n.MessageService;

import java.util.Collections;
import java.util.List;

public abstract class BaseCommand implements CommandExecutor, TabCompleter {

    protected final MessageService msg;

    protected BaseCommand(MessageService msg) {
        this.msg = msg;
    }

    protected Player requirePlayer(CommandSender sender) {
        if (!(sender instanceof Player p)) {
            msg.send(sender, "errors.players-only");
            return null;
        }
        return p;
    }

    protected boolean requirePerm(CommandSender sender) {
        if (!sender.hasPermission("serverauth.use")) {
            msg.send(sender, "errors.no-permission");
            return false;
        }
        return true;
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
        return Collections.emptyList();
    }
}

