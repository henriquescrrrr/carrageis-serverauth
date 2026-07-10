package pt.henrique.serverauth.api.events;

import org.bukkit.entity.Player;
import org.bukkit.event.HandlerList;
import org.bukkit.event.player.PlayerEvent;
import org.jetbrains.annotations.NotNull;

/**
 * Fired when a player becomes fully authenticated (password + 2FA if enabled).
 */
public class PlayerFullyAuthenticatedEvent extends PlayerEvent {
    private static final HandlerList HANDLERS = new HandlerList();

    public PlayerFullyAuthenticatedEvent(@NotNull Player who) {
        super(who);
    }

    @Override
    public @NotNull HandlerList getHandlers() {
        return HANDLERS;
    }

    public static HandlerList getHandlerList() {
        return HANDLERS;
    }
}

