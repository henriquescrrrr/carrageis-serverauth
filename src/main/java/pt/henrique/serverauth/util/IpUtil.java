package pt.henrique.serverauth.util;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;

public final class IpUtil {
    private IpUtil() {}

    /**
     * Normalize an InetAddress to a consistent string representation.
     * - IPv4-mapped IPv6 (::ffff:x.x.x.x) → converted to plain IPv4 string
     * - IPv6 → full lowercase, no leading zeros, standard compression, scope ID stripped
     * - IPv4 → standard dotted decimal
     * - Null → "unknown"
     */
    public static String normalizeIp(InetAddress address) {
        if (address == null) return "unknown";

        // Handle IPv4-mapped IPv6 addresses
        if (address instanceof Inet6Address ipv6) {
            if (ipv6.isIPv4CompatibleAddress() || isIPv4Mapped(ipv6)) {
                byte[] bytes = ipv6.getAddress();
                return (bytes[12] & 0xFF) + "." + (bytes[13] & 0xFF) + "."
                     + (bytes[14] & 0xFF) + "." + (bytes[15] & 0xFF);
            }
            // Standard IPv6 — use getHostAddress() which handles compression, strip scope ID
            return ipv6.getHostAddress().toLowerCase().split("%")[0];
        }

        return address.getHostAddress();
    }

    private static boolean isIPv4Mapped(Inet6Address address) {
        byte[] bytes = address.getAddress();
        // First 10 bytes must be 0, bytes 10-11 must be 0xFF
        for (int i = 0; i < 10; i++) {
            if (bytes[i] != 0) return false;
        }
        return bytes[10] == (byte) 0xFF && bytes[11] == (byte) 0xFF;
    }

    /**
     * Extract and normalize IP from a player's socket address.
     */
    public static String fromPlayer(InetSocketAddress socketAddress) {
        if (socketAddress == null) return "unknown";
        return normalizeIp(socketAddress.getAddress());
    }

    /**
     * Compare two IP strings for equality after normalization.
     * Both strings should already be normalized, but this adds safety.
     */
    public static boolean ipEquals(String ip1, String ip2) {
        if (ip1 == null || ip2 == null) return false;
        return ip1.equalsIgnoreCase(ip2);
    }

    /**
     * Backwards-compatible method — delegates to normalizeIp.
     */
    public static String ipString(InetAddress address) {
        return normalizeIp(address);
    }
}

