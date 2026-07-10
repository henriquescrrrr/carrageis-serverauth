package pt.henrique.serverauth.listeners;

import org.bukkit.command.CommandExecutor;
import org.bukkit.command.PluginCommand;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.plugin.java.JavaPlugin;
import pt.henrique.serverauth.auth.LockdownService;
import pt.henrique.serverauth.i18n.MessageService;

import java.util.*;
import java.util.logging.Logger;

/**
 * Intercepts sensitive auth commands BEFORE the server logs them,
 * cancels the event (preventing the raw text from reaching console),
 * and manually dispatches to the correct command handler.
 *
 * This ensures passwords, 2FA codes, and recovery answers never
 * appear in console/log files.
 */
public final class CommandRedactionListener implements Listener {

    private final JavaPlugin plugin;
    private final Logger logger;
    private final LockdownService lockdown;
    private final MessageService msg;

    /**
     * Map of base command name → CommandExecutor.
     * Includes all aliases (e.g. "cpw" → ChangePasswordCommand).
     */
    private final Map<String, CommandExecutor> sensitiveCommands;

    /**
     * Set of base commands where ALL subcommands/args are sensitive.
     * For commands like /recover where only some sub-paths are sensitive,
     * we handle them specially in {@link #isSensitive(String, String[])}.
     */
    private static final Set<String> FULLY_SENSITIVE = Set.of(
            "login", "register", "changepassword", "cpw"
    );

    /**
     * Commands where only specific subcommands are sensitive.
     * key = base command, value = set of sensitive first-argument values.
     */
    private static final Map<String, Set<String>> PARTIALLY_SENSITIVE = Map.of(
            "2fa", Set.of("code", "verify", "confirm", "disable"),
            "twofa", Set.of("code", "verify", "confirm", "disable"),
            "totp", Set.of("code", "verify", "confirm", "disable"),
            "recover", Set.of("answer", "2fa", "code", "setpassword"),
            "recovery", Set.of("setanswer"),
            "authadmin", Set.of("setpassword", "setpw", "delete", "unregister", "reset2fa", "resettotp")
    );

    public CommandRedactionListener(JavaPlugin plugin, Map<String, CommandExecutor> sensitiveCommands,
                                    LockdownService lockdown, MessageService msg) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.sensitiveCommands = sensitiveCommands;
        this.lockdown = lockdown;
        this.msg = msg;
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onCommand(PlayerCommandPreprocessEvent e) {
        if (e.isCancelled()) return;

        String message = e.getMessage();
        if (!message.startsWith("/")) return;

        // Parse: "/login password" → label="login", args=["password"]
        String withoutSlash = message.substring(1);
        String[] parts = withoutSlash.split("\\s+");
        if (parts.length == 0) return;

        String label = parts[0].toLowerCase(Locale.ROOT);
        String[] args = Arrays.copyOfRange(parts, 1, parts.length);

        if (!isSensitive(label, args)) return;

        // Cancel the event → prevents server from logging the raw command text
        e.setCancelled(true);

        Player p = e.getPlayer();

        // Lockdown check: since we cancel the event, the LockdownListener won't see it.
        // We must enforce lockdown rules ourselves.
        if (lockdown.isLocked(p) && !lockdown.isCommandAllowed(message)) {
            msg.send(p, "errors.command-blocked");
            return;
        }

        // Log a safe redacted line
        logger.info(p.getName() + " used /" + redact(label, args));

        // Dispatch to the correct handler
        CommandExecutor executor = sensitiveCommands.get(label);
        if (executor == null) {
            // Try to resolve via alias → actual command name
            PluginCommand pc = plugin.getServer().getPluginCommand(label);
            if (pc != null) {
                executor = sensitiveCommands.get(pc.getName().toLowerCase(Locale.ROOT));
            }
        }

        if (executor != null) {
            PluginCommand pc = plugin.getServer().getPluginCommand(label);
            if (pc == null) return;
            executor.onCommand(p, pc, label, args);
        }
    }

    private boolean isSensitive(String label, String[] args) {
        if (FULLY_SENSITIVE.contains(label)) return true;

        Set<String> subCmds = PARTIALLY_SENSITIVE.get(label);
        if (subCmds != null && args.length >= 1) {
            return subCmds.contains(args[0].toLowerCase(Locale.ROOT));
        }
        return false;
    }

    /**
     * Build a redacted log string. Shows the command structure but hides values.
     */
    private String redact(String label, String[] args) {
        if (FULLY_SENSITIVE.contains(label)) {
            // e.g. /login [REDACTED], /register [REDACTED] [REDACTED]
            StringBuilder sb = new StringBuilder(label);
            for (int i = 0; i < args.length; i++) {
                sb.append(" [REDACTED]");
            }
            return sb.toString();
        }

        // Partially sensitive: show subcommand, redact the rest
        if (args.length == 0) return label;
        StringBuilder sb = new StringBuilder(label).append(" ").append(args[0]);
        for (int i = 1; i < args.length; i++) {
            sb.append(" [REDACTED]");
        }
        return sb.toString();
    }
}



