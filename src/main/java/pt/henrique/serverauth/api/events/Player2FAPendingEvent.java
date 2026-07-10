package pt.henrique.serverauth.api.events;

import org.bukkit.entity.Player;
import org.bukkit.event.HandlerList;
import org.bukkit.event.player.PlayerEvent;
import org.jetbrains.annotations.NotNull;

/**
 * Fired when a player has entered their password correctly but still needs to verify 2FA.
 */
public class Player2FAPendingEvent extends PlayerEvent {
    private static final HandlerList HANDLERS = new HandlerList();

    public Player2FAPendingEvent(@NotNull Player who) {
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

