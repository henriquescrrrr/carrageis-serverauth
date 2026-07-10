package pt.henrique.serverauth.api.events;

import org.bukkit.entity.Player;
import org.bukkit.event.HandlerList;
import org.bukkit.event.player.PlayerEvent;
import org.jetbrains.annotations.NotNull;

/**
 * Fired when a player enables or disables 2FA.
 */
public class Player2FAStateChangeEvent extends PlayerEvent {
    private static final HandlerList HANDLERS = new HandlerList();

    private final boolean enabled;

    public Player2FAStateChangeEvent(@NotNull Player who, boolean enabled) {
        super(who);
        this.enabled = enabled;
    }

    /** Whether 2FA is now enabled (true) or disabled (false). */
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public @NotNull HandlerList getHandlers() {
        return HANDLERS;
    }

    public static HandlerList getHandlerList() {
        return HANDLERS;
    }
}

