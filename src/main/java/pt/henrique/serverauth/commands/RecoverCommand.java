package pt.henrique.serverauth.commands;

import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import pt.henrique.serverauth.auth.AuthService;
import pt.henrique.serverauth.config.PluginConfig;
import pt.henrique.serverauth.i18n.MessageService;

import java.util.List;
import java.util.StringJoiner;

public final class RecoverCommand extends BaseCommand {

    private final PluginConfig cfg;
    private final AuthService auth;

    public RecoverCommand(PluginConfig cfg, MessageService msg, AuthService auth) {
        super(msg);
        this.cfg = cfg;
        this.auth = auth;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!requirePerm(sender)) return true;
        Player p = requirePlayer(sender);
        if (p == null) return true;

        if (args.length == 0) {
            auth.recoverShowQuestion(p);
            return true;
        }

        String sub = args[0].toLowerCase();
        switch (sub) {
            case "answer" -> {
                if (args.length < 2) {
                    msg.send(p, "recover.answer-usage");
                    return true;
                }
                auth.recoverAnswer(p, join(args, 1));
            }
            case "2fa", "code" -> {
                // Recovery via 2FA code (when 2FA is enabled)
                if (args.length < 2) {
                    msg.send(p, "recover.2fa-usage");
                    return true;
                }
                auth.recoverWith2FA(p, args[1]);
            }
            case "setpassword" -> {
                if (args.length < 3) {
                    msg.send(p, "recover.setpassword-usage");
                    return true;
                }
                auth.recoverSetPassword(p, args[1], args[2]);
            }
            default -> msg.send(p, "recover.usage");
        }
        return true;
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
        if (args.length == 1) return List.of("answer", "2fa", "setpassword");
        return List.of();
    }

    private static String join(String[] args, int start) {
        StringJoiner sj = new StringJoiner(" ");
        for (int i = start; i < args.length; i++) sj.add(args[i]);
        return sj.toString();
    }
}
