package pt.henrique.serverauth.api.events;

import org.bukkit.entity.Player;
import org.bukkit.event.HandlerList;
import org.bukkit.event.player.PlayerEvent;
import org.jetbrains.annotations.NotNull;

/**
 * Fired when a player successfully authenticates with their password.
 * If 2FA is required, this fires BEFORE 2FA verification.
 */
public class PlayerAuthSuccessEvent extends PlayerEvent {
    private static final HandlerList HANDLERS = new HandlerList();

    public PlayerAuthSuccessEvent(@NotNull Player who) {
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

