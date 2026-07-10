package pt.henrique.serverauth.commands;

import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import pt.henrique.serverauth.auth.AuthService;
import pt.henrique.serverauth.config.PluginConfig;
import pt.henrique.serverauth.i18n.MessageService;

import java.util.StringJoiner;

public final class RecoveryCommand extends BaseCommand {

    private final PluginConfig cfg;
    private final AuthService auth;

    public RecoveryCommand(PluginConfig cfg, MessageService msg, AuthService auth) {
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
            msg.send(p, "recover.usage");
            return true;
        }

        String sub = args[0].toLowerCase();
        switch (sub) {
            case "setquestion" -> {
                if (args.length < 2) {
                    msg.send(p, "recovery.setquestion-usage");
                    return true;
                }
                auth.setRecoveryQuestion(p, join(args, 1));
            }
            case "setanswer" -> {
                if (args.length < 2) {
                    msg.send(p, "recovery.setanswer-usage");
                    return true;
                }
                auth.setRecoveryAnswer(p, join(args, 1));
            }
            case "status" -> auth.recoveryStatus(p);
            default -> msg.send(p, "recover.usage");
        }
        return true;
    }

    private static String join(String[] args, int start) {
        StringJoiner sj = new StringJoiner(" ");
        for (int i = start; i < args.length; i++) sj.add(args[i]);
        return sj.toString();
    }
}

