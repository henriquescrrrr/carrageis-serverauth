package pt.henrique.serverauth.storage.sql;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.bukkit.plugin.Plugin;
import pt.henrique.serverauth.config.PluginConfig;

import javax.sql.DataSource;
import java.io.File;

public final class HikariDataSourceFactory {
    private HikariDataSourceFactory() {}

    public static DataSource create(Plugin plugin, PluginConfig.StorageConfig cfg) {
        HikariConfig hc = new HikariConfig();
        hc.setPoolName("ServerAUTH");
        hc.setMaximumPoolSize(5);
        hc.setMinimumIdle(1);
        hc.setConnectionTimeout(10_000);
        hc.setLeakDetectionThreshold(0);

        if (cfg.type() == PluginConfig.StorageType.MYSQL) {
            String jdbc = "jdbc:mysql://" + cfg.mysql().host() + ":" + cfg.mysql().port() + "/" + cfg.mysql().database() +
                    "?useSSL=" + cfg.mysql().useSsl() + "&allowPublicKeyRetrieval=true&characterEncoding=utf8";
            hc.setJdbcUrl(jdbc);
            hc.setUsername(cfg.mysql().username());
            hc.setPassword(cfg.mysql().password());
            hc.addDataSourceProperty("cachePrepStmts", "true");
            hc.addDataSourceProperty("prepStmtCacheSize", "250");
            hc.addDataSourceProperty("prepStmtCacheSqlLimit", "2048");
        } else {
            File dbFile = new File(plugin.getDataFolder(), cfg.sqlite().file());
            dbFile.getParentFile().mkdirs();
            String jdbc = "jdbc:sqlite:" + dbFile.getAbsolutePath();
            hc.setJdbcUrl(jdbc);
        }

        return new HikariDataSource(hc);
    }

    public static void closeQuietly(DataSource ds) {
        if (ds instanceof HikariDataSource hk) {
            try {
                hk.close();
            } catch (Exception ignored) {
            }
        }
    }
}

