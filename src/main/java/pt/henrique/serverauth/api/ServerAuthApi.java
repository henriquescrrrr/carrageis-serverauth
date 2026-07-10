package pt.henrique.serverauth.api;

import java.util.OptionalLong;
import java.util.UUID;

/**
 * Public API for ServerAUTH. Obtain via:
 * <pre>
 *   ServerAuthApi api = Bukkit.getServicesManager().load(ServerAuthApi.class);
 * </pre>
 */
public interface ServerAuthApi {

    /**
     * Returns true if the player has a registered account.
     */
    boolean isRegistered(UUID playerId);

    /**
     * Returns true if the player has successfully entered their password
     * (may still be pending 2FA verification).
     */
    boolean isPasswordAuthenticated(UUID playerId);

    /**
     * Returns true if the player is fully authenticated:
     * password OK + 2FA verified (if enabled).
     */
    boolean isFullyAuthenticated(UUID playerId);

    /**
     * Returns true if the player has 2FA enabled on their account.
     */
    boolean is2faEnabled(UUID playerId);

    /**
     * Returns true if 2FA is required for this player
     * (e.g., due to being OP or a privileged role set by ServerRoles).
     */
    boolean is2faRequired(UUID playerId);

    /**
     * Set whether 2FA is required for a player.
     * Intended for use by ServerRoles or similar plugins to enforce 2FA policies.
     */
    void set2faRequired(UUID playerId, boolean required);

    /**
     * Force-logout a player with a reason message.
     */
    void forceLogout(UUID playerId, String reason);

    /**
     * Returns the epoch millis of the last successful 2FA verification, if available.
     */
    OptionalLong getLast2faSuccessMillis(UUID playerId);

    /**
     * Returns remaining seconds of 2FA lockout, or 0 if not locked out.
     */
    int getRemainingLockoutSeconds(UUID playerId);
}

