package pt.henrique.serverauth.storage.sql.migrate;

import pt.henrique.serverauth.config.PluginConfig;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public final class SchemaMigrator {
    private SchemaMigrator() {}

    public static void migrate(DataSource ds, PluginConfig.StorageType type) {
        try (Connection c = ds.getConnection()) {
            c.setAutoCommit(true);

            exec(c, "CREATE TABLE IF NOT EXISTS auth_meta (k VARCHAR(50) PRIMARY KEY, v VARCHAR(50) NOT NULL)");

            int version = readSchemaVersion(c);
            if (version < 1) {
                applyV1(c, type);
                writeSchemaVersion(c, 1);
                version = 1;
            }
            if (version < 2) {
                applyV2(c, type);
                writeSchemaVersion(c, 2);
                version = 2;
            }
            if (version < 3) {
                applyV3(c, type);
                writeSchemaVersion(c, 3);
                version = 3;
            }
            if (version < 4) {
                applyV4(c, type);
                writeSchemaVersion(c, 4);
                version = 4;
            }
            if (version < 5) {
                applyV5(c, type);
                writeSchemaVersion(c, 5);
            }

            // Safety: always ensure V4+ columns exist even if schema_version is stale
            addColumnIfNotExists(c, type, "auth_users", "last_logout_location", "TEXT");
            addColumnIfNotExists(c, type, "auth_users", "uuid", "VARCHAR(36)");
            addColumnIfNotExists(c, type, "auth_users", "client_brand", "VARCHAR(128)");
            addColumnIfNotExists(c, type, "auth_users", "client_settings_hash", "VARCHAR(64)");
            addColumnIfNotExists(c, type, "auth_users", "last_client_fingerprint", "VARCHAR(200)");

        } catch (Exception e) {
            throw new IllegalStateException("Failed to migrate ServerAUTH schema: " + e.getMessage(), e);
        }
    }

    private static int readSchemaVersion(Connection c) {
        try (Statement st = c.createStatement()) {
            try (ResultSet rs = st.executeQuery("SELECT v FROM auth_meta WHERE k='schema_version'")) {
                if (rs.next()) {
                    return Integer.parseInt(rs.getString(1));
                }
            }
        } catch (Exception ignored) {
        }
        return 0;
    }

    private static void writeSchemaVersion(Connection c, int version) throws Exception {
        exec(c, "DELETE FROM auth_meta WHERE k='schema_version'");
        exec(c, "INSERT INTO auth_meta (k, v) VALUES ('schema_version', '" + version + "')");
    }

    private static void applyV1(Connection c, PluginConfig.StorageType type) throws Exception {
        // NOTE: Keep this SQL extremely explicit to avoid dialect bugs.
        String idDef = (type == PluginConfig.StorageType.MYSQL)
                ? "id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY"
                : "id INTEGER PRIMARY KEY AUTOINCREMENT";

        String createUsers = "CREATE TABLE IF NOT EXISTS auth_users (" +
                idDef + "," +
                "username_lower VARCHAR(32) NOT NULL UNIQUE," +
                "username_original VARCHAR(32) NOT NULL," +
                "password_hash VARCHAR(100) NOT NULL," +
                "registration_time BIGINT NOT NULL," +
                "last_login_time BIGINT NOT NULL," +
                "last_ip VARCHAR(64) NOT NULL," +
                "autologin_enabled " + boolType(type) + " NOT NULL," +
                "trusted_ip_1 VARCHAR(64)," +
                "trusted_ip_1_score BIGINT NOT NULL," +
                "trusted_ip_2 VARCHAR(64)," +
                "trusted_ip_2_score BIGINT NOT NULL," +
                "recovery_question TEXT," +
                "recovery_answer_hash VARCHAR(100)," +
                "login_attempts INT NOT NULL," +
                "login_lockout_until BIGINT NOT NULL," +
                "recovery_attempts INT NOT NULL," +
                "recovery_lockout_until BIGINT NOT NULL," +
                "last_session_time BIGINT NOT NULL" +
                ")";

        exec(c, createUsers);
        exec(c, "CREATE INDEX IF NOT EXISTS idx_auth_users_username_lower ON auth_users(username_lower)");
    }

    private static void applyV2(Connection c, PluginConfig.StorageType type) throws Exception {
        // 2FA columns
        addColumnIfNotExists(c, type, "auth_users", "two_factor_enabled", boolType(type) + " NOT NULL DEFAULT 0");
        addColumnIfNotExists(c, type, "auth_users", "totp_secret", "VARCHAR(64)");
        addColumnIfNotExists(c, type, "auth_users", "backup_codes_json", "TEXT");
        addColumnIfNotExists(c, type, "auth_users", "last_two_factor_success", "BIGINT NOT NULL DEFAULT 0");
        addColumnIfNotExists(c, type, "auth_users", "two_factor_attempts", "INT NOT NULL DEFAULT 0");
        addColumnIfNotExists(c, type, "auth_users", "two_factor_lockout_until", "BIGINT NOT NULL DEFAULT 0");
        addColumnIfNotExists(c, type, "auth_users", "two_factor_required", boolType(type) + " NOT NULL DEFAULT 0");
    }

    private static void applyV3(Connection c, PluginConfig.StorageType type) throws Exception {
        // IP-based 2FA skip: store last IP that completed 2FA verification
        addColumnIfNotExists(c, type, "auth_users", "last_2fa_verified_ip", "VARCHAR(64)");
    }

    private static void applyV4(Connection c, PluginConfig.StorageType type) throws Exception {
        // Store last logout location to teleport player back after authentication
        addColumnIfNotExists(c, type, "auth_users", "last_logout_location", "TEXT");
    }

    private static void applyV5(Connection c, PluginConfig.StorageType type) throws Exception {
        // Add UUID column — stores player's Mojang UUID
        addColumnIfNotExists(c, type, "auth_users", "uuid", "VARCHAR(36)");

        // Add client fingerprint columns
        addColumnIfNotExists(c, type, "auth_users", "client_brand", "VARCHAR(128)");
        addColumnIfNotExists(c, type, "auth_users", "client_settings_hash", "VARCHAR(64)");
        addColumnIfNotExists(c, type, "auth_users", "last_client_fingerprint", "VARCHAR(200)");

        // Add UUID index for fast lookups
        try (var stmt = c.createStatement()) {
            stmt.executeUpdate("CREATE INDEX IF NOT EXISTS idx_auth_users_uuid ON auth_users(uuid)");
        }
    }

    private static void addColumnIfNotExists(Connection c, PluginConfig.StorageType type, String table, String column, String def) throws Exception {
        if (type == PluginConfig.StorageType.MYSQL) {
            // MySQL: check INFORMATION_SCHEMA
            try (var ps = c.prepareStatement(
                    "SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME=? AND COLUMN_NAME=?")) {
                ps.setString(1, table);
                ps.setString(2, column);
                try (var rs = ps.executeQuery()) {
                    if (rs.next() && rs.getInt(1) > 0) return;
                }
            }
        } else {
            // SQLite: PRAGMA table_info
            try (var st = c.createStatement(); var rs = st.executeQuery("PRAGMA table_info(" + table + ")")) {
                while (rs.next()) {
                    if (column.equalsIgnoreCase(rs.getString("name"))) return;
                }
            }
        }
        exec(c, "ALTER TABLE " + table + " ADD COLUMN " + column + " " + def);
    }

    private static String boolType(PluginConfig.StorageType type) {
        return type == PluginConfig.StorageType.MYSQL ? "TINYINT(1)" : "INTEGER";
    }

    private static void exec(Connection c, String sql) throws Exception {
        try (Statement st = c.createStatement()) {
            st.execute(sql);
        }
    }
}
