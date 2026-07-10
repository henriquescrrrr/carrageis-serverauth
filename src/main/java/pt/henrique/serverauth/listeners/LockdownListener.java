package pt.henrique.serverauth.listeners;

import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.block.BlockPlaceEvent;
import org.bukkit.event.entity.EntityDamageByEntityEvent;
import org.bukkit.event.entity.EntityDamageEvent;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.inventory.InventoryDragEvent;
import org.bukkit.event.inventory.InventoryOpenEvent;
import org.bukkit.event.player.*;
import io.papermc.paper.event.player.AsyncChatEvent;
import org.bukkit.event.vehicle.VehicleEnterEvent;
import pt.henrique.serverauth.auth.LockdownService;
import pt.henrique.serverauth.config.PluginConfig;
import pt.henrique.serverauth.i18n.MessageService;

public final class LockdownListener implements Listener {

    private final PluginConfig cfg;
    private final MessageService msg;
    private final LockdownService lockdown;

    public LockdownListener(PluginConfig cfg, MessageService msg, LockdownService lockdown) {
        this.cfg = cfg;
        this.msg = msg;
        this.lockdown = lockdown;
    }

    private boolean locked(Player p) {
        return lockdown.isLocked(p);
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onMove(PlayerMoveEvent e) {
        if (!cfg.lockdown().enabled()) return;
        Player p = e.getPlayer();
        if (!locked(p)) return;
        if (e.getFrom().getBlockX() != e.getTo().getBlockX() || e.getFrom().getBlockY() != e.getTo().getBlockY() || e.getFrom().getBlockZ() != e.getTo().getBlockZ()) {
            e.setTo(e.getFrom());
        }
    }

    // Use Paper's modern AsyncChatEvent (guaranteed to fire for ALL player chat on
    // 1.21.11, including signed messages). The legacy AsyncPlayerChatEvent is only
    // fired by a compatibility bridge and is deprecated for removal — an auth gate
    // must not rely on it, or an unauthenticated player could leak chat.
    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onChat(AsyncChatEvent e) {
        if (!cfg.lockdown().enabled()) return;
        if (locked(e.getPlayer())) {
            e.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onCommand(PlayerCommandPreprocessEvent e) {
        if (!cfg.lockdown().enabled()) return;
        Player p = e.getPlayer();
        if (!locked(p)) return;

        if (!lockdown.isCommandAllowed(e.getMessage())) {
            e.setCancelled(true);
            msg.send(p, "errors.command-blocked");
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onInteract(PlayerInteractEvent e) {
        if (!cfg.lockdown().enabled()) return;
        if (locked(e.getPlayer())) {
            e.setCancelled(true);
            lockdown.deny(e.getPlayer());
        }
    }

    // Right-clicking entities (villagers/trading, item frames, armor stands, boats, ...)
    // is NOT a PlayerInteractEvent — it needs its own handler. This also covers
    // PlayerInteractAtEntityEvent / armor-stand manipulation (shared handler list).
    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onInteractEntity(PlayerInteractEntityEvent e) {
        if (!cfg.lockdown().enabled()) return;
        if (locked(e.getPlayer())) {
            e.setCancelled(true);
            lockdown.deny(e.getPlayer());
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onBucketEmpty(PlayerBucketEmptyEvent e) {
        if (!cfg.lockdown().enabled()) return;
        if (locked(e.getPlayer())) {
            e.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onBucketFill(PlayerBucketFillEvent e) {
        if (!cfg.lockdown().enabled()) return;
        if (locked(e.getPlayer())) {
            e.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onBedEnter(PlayerBedEnterEvent e) {
        if (!cfg.lockdown().enabled()) return;
        if (locked(e.getPlayer())) {
            e.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onVehicleEnter(VehicleEnterEvent e) {
        if (!cfg.lockdown().enabled()) return;
        if (e.getEntered() instanceof Player p && locked(p)) {
            e.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onDrop(PlayerDropItemEvent e) {
        if (!cfg.lockdown().enabled()) return;
        if (locked(e.getPlayer())) {
            e.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onPickup(PlayerAttemptPickupItemEvent e) {
        if (!cfg.lockdown().enabled()) return;
        if (locked(e.getPlayer())) {
            e.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onInvOpen(InventoryOpenEvent e) {
        if (!cfg.lockdown().enabled()) return;
        if (e.getPlayer() instanceof Player p && locked(p)) {
            e.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onInvClick(InventoryClickEvent e) {
        if (!cfg.lockdown().enabled()) return;
        if (e.getWhoClicked() instanceof Player p && locked(p)) {
            e.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onInvDrag(InventoryDragEvent e) {
        if (!cfg.lockdown().enabled()) return;
        if (e.getWhoClicked() instanceof Player p && locked(p)) {
            e.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onBreak(BlockBreakEvent e) {
        if (!cfg.lockdown().enabled()) return;
        if (locked(e.getPlayer())) {
            e.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onPlace(BlockPlaceEvent e) {
        if (!cfg.lockdown().enabled()) return;
        if (locked(e.getPlayer())) {
            e.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onDamage(EntityDamageEvent e) {
        if (!cfg.lockdown().enabled()) return;
        if (e.getEntity() instanceof Player p && locked(p)) {
            e.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onDamageByEntity(EntityDamageByEntityEvent e) {
        if (!cfg.lockdown().enabled()) return;
        if (e.getDamager() instanceof Player p && locked(p)) {
            e.setCancelled(true);
        }
        if (e.getEntity() instanceof Player p2 && locked(p2)) {
            e.setCancelled(true);
        }
    }
}

