package pt.henrique.serverauth;

import org.bukkit.Bukkit;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.PluginCommand;
import org.bukkit.command.TabCompleter;
import org.bukkit.plugin.ServicePriority;
import org.bukkit.plugin.java.JavaPlugin;
import pt.henrique.serverauth.api.ServerAuthApi;
import pt.henrique.serverauth.api.ServerAuthApiImpl;
import pt.henrique.serverauth.auth.*;
import pt.henrique.serverauth.commands.*;
import pt.henrique.serverauth.config.PluginConfig;
import pt.henrique.serverauth.hook.PlayerSettingsHook;
import pt.henrique.serverauth.i18n.MessageService;
import pt.henrique.serverauth.listeners.CommandRedactionListener;
import pt.henrique.serverauth.listeners.LockdownListener;
import pt.henrique.serverauth.listeners.PlayerConnectionListener;
import pt.henrique.serverauth.security.BCryptHasher;
import pt.henrique.serverauth.security.PasswordHasher;
import pt.henrique.serverauth.security.SecurityLogger;
import pt.henrique.serverauth.storage.UserRepository;
import pt.henrique.serverauth.storage.sql.HikariDataSourceFactory;
import pt.henrique.serverauth.storage.sql.SqlUserRepository;
import pt.henrique.serverauth.storage.sql.migrate.SchemaMigrator;
import pt.henrique.serverauth.util.Async;
import pt.henrique.serverauth.web.SetupWebServer;

import javax.sql.DataSource;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public final class ServerAUTH extends JavaPlugin {

    private PluginConfig config;
    private MessageService messages;

    private Async async;
    private DataSource dataSource;

    private SessionService sessionService;
    private AuthService authService;
    private LockdownService lockdownService;
    private TwoFactorService twoFactorService;
    private ClientFingerprintService fingerprintService;
    private SecurityLogger securityLogger;
    private SetupWebServer webServer;
    private PlayerSettingsHook settingsHook;

    @Override
    public void onEnable() {
        saveDefaultConfig();
        this.config = PluginConfig.load(getConfig());

        this.messages = new MessageService(this, config.language());

        // PlayerSettings hook — per-player language
        this.settingsHook = new PlayerSettingsHook();
        settingsHook.init(getLogger());
        settingsHook.registerSettings();
        this.messages.setPlayerSettingsHook(settingsHook);

        this.messages.reload();

        this.async = new Async(this);

        this.dataSource = HikariDataSourceFactory.create(this, config.storage());
        SchemaMigrator.migrate(dataSource, config.storage().type());

        UserRepository userRepository = new SqlUserRepository(dataSource, config.storage().type());
        PasswordHasher passwordHasher = new BCryptHasher(config.security().bcryptCost());

        this.sessionService = new SessionService(config);
        this.authService = new AuthService(this, config, messages, async, userRepository, passwordHasher, sessionService, settingsHook);
        this.lockdownService = new LockdownService(config, messages, authService, userRepository, async);
        this.authService.setLockdownService(lockdownService);
        this.twoFactorService = new TwoFactorService(this, config, messages, async, userRepository, passwordHasher, sessionService, lockdownService);
        this.authService.setTwoFactorService(twoFactorService);

        // Security logger — centralised security event file + OP notifications
        this.securityLogger = new SecurityLogger(config, messages, getLogger(), getDataFolder());
        this.authService.setSecurityLogger(securityLogger);
        this.twoFactorService.setSecurityLogger(securityLogger);

        // Client fingerprint service — captures client brand + settings hash
        this.fingerprintService = new ClientFingerprintService();
        getServer().getMessenger().registerIncomingPluginChannel(this, "minecraft:brand", fingerprintService);
        getServer().getPluginManager().registerEvents(fingerprintService, this);
        this.authService.setFingerprintService(fingerprintService);
        this.twoFactorService.setFingerprintService(fingerprintService);

        // Start built-in web server for 2FA setup
        this.webServer = new SetupWebServer(config, twoFactorService, getLogger());
        webServer.start();

        // Register public API
        var api = new ServerAuthApiImpl(authService, sessionService, userRepository, messages, async);
        getServer().getServicesManager().register(ServerAuthApi.class, api, this, ServicePriority.Normal);

        registerCommands();
        registerListeners();

        // Periodic darkness refresh + cleanup
        Bukkit.getScheduler().runTaskTimer(this, () -> {
            if (config.lockdown().enabled() && config.lockdown().applyDarkness()) {
                lockdownService.refreshDarknessForUnauthenticated();
            }
            sessionService.cleanupExpiredGrace();
            twoFactorService.cleanupExpiredTokens();
        }, 40L, 40L);

        // Repeating login/register/2FA title reminders
        new TitleReminderService(this, config, messages, authService).start();

        // Backfill UUID for online players whose records have uuid IS NULL
        backfillUuidsForOnlinePlayers(userRepository);

        getLogger().info("ServerAUTH enabled.");
    }

    /**
     * For any online player whose DB record has no UUID stored yet, backfill it.
     * This handles existing accounts created before the UUID column was added.
     */
    private void backfillUuidsForOnlinePlayers(UserRepository repo) {
        async.run(() -> {
            for (org.bukkit.entity.Player p : getServer().getOnlinePlayers()) {
                try {
                    String lower = p.getName().toLowerCase(java.util.Locale.ROOT);
                    repo.findByUsernameLower(lower).ifPresent(u -> {
                        if (u.uuid() == null || u.uuid().isBlank()) {
                            repo.updateUuid(u.id(), p.getUniqueId().toString());
                            getLogger().info("Backfilled UUID for " + p.getName());
                        }
                    });
                } catch (Exception e) {
                    getLogger().warning("Failed to backfill UUID for " + p.getName() + ": " + e.getMessage());
                }
            }
        });
    }

    @Override
    public void onDisable() {
        if (settingsHook != null) settingsHook.unregisterSettings();
        if (webServer != null) webServer.stop();
        getServer().getMessenger().unregisterIncomingPluginChannel(this);
        getServer().getServicesManager().unregisterAll(this);
        if (async != null) async.shutdown();
        HikariDataSourceFactory.closeQuietly(dataSource);
    }

    public PluginConfig cfg() {
        return config;
    }

    public MessageService msg() {
        return messages;
    }

    /**
     * Reloads the plugin configuration and language files from disk.
     * Does NOT re-create database connections or services — only refreshes
     * config values and message strings.
     */
    public void performReload() {
        reloadConfig();
        this.config = PluginConfig.load(getConfig());
        this.messages.reload();
        getLogger().info("ServerAUTH configuration reloaded.");
    }

    private void registerListeners() {
        Bukkit.getPluginManager().registerEvents(
                new PlayerConnectionListener(this, config, messages, authService, lockdownService), this);
        Bukkit.getPluginManager().registerEvents(
                new LockdownListener(config, messages, lockdownService), this);
    }

    private void registerCommands() {
        var loginCmd = new LoginCommand(config, messages, authService);
        var registerCmd = new RegisterCommand(config, messages, authService);
        var changePwCmd = new ChangePasswordCommand(config, messages, authService);
        var logoutCmd = new LogoutCommand(config, messages, authService);
        var autoLoginCmd = new AutoLoginCommand(config, messages, authService);
        var recoveryCmd = new RecoveryCommand(config, messages, authService);
        var recoverCmd = new RecoverCommand(config, messages, authService);
        var twofaCmd = new TwoFactorCommand(this, config, messages, authService, twoFactorService);
        var helpExecutor = new AuthHelpCommand(config, messages, authService);
        var adminCmd = new AuthAdminCommand(this, messages, authService, twoFactorService);

        bind("register", registerCmd);
        bind("login", loginCmd);
        bind("changepassword", changePwCmd);
        bind("logout", logoutCmd);
        bind("autologin", autoLoginCmd);
        bind("recovery", recoveryCmd);
        bind("recover", recoverCmd);
        bind("2fa", twofaCmd);
        bind("authhelp", helpExecutor);
        bind("authadmin", adminCmd);

        PluginCommand help = getCommand("help");
        if (help != null) {
            if (config.overrideHelpCommand()) {
                help.setExecutor(helpExecutor);
                help.setTabCompleter(helpExecutor);
            } else {
                help.setExecutor(null);
                help.setTabCompleter(null);
            }
        }

        // Register command redaction listener to prevent passwords/codes from appearing in logs
        Map<String, org.bukkit.command.CommandExecutor> sensitiveMap = new LinkedHashMap<>();
        sensitiveMap.put("login", loginCmd);
        sensitiveMap.put("register", registerCmd);
        sensitiveMap.put("changepassword", changePwCmd);
        sensitiveMap.put("cpw", changePwCmd);           // alias
        sensitiveMap.put("2fa", twofaCmd);
        sensitiveMap.put("twofa", twofaCmd);             // alias
        sensitiveMap.put("totp", twofaCmd);              // alias
        sensitiveMap.put("recover", recoverCmd);
        sensitiveMap.put("recovery", recoveryCmd);
        sensitiveMap.put("authadmin", adminCmd);
        Bukkit.getPluginManager().registerEvents(
                new CommandRedactionListener(this, sensitiveMap, lockdownService, messages), this);
    }

    private void bind(String name, CommandExecutor executor) {
        PluginCommand cmd = Objects.requireNonNull(getCommand(name), "Command not found in plugin.yml: " + name);
        cmd.setExecutor(executor);
        if (executor instanceof TabCompleter tab) {
            cmd.setTabCompleter(tab);
        }
    }
}
