# ServerAUTH

A secure authentication plugin for **Paper/Purpur 1.21.x** with **Two-Factor Authentication (2FA)**, browser-based setup, and a public API for other plugins.

---

## Features

- **Registration & Login** — `/register`, `/login` with BCrypt-hashed passwords
- **Console Security** — sensitive commands (passwords, 2FA codes) are **redacted from console logs**
- **Lockdown + Darkness** — players can't move, interact, or chat until authenticated
- **Auto-login** — trusted IP recognition for returning players
- **Recovery questions** — `/recovery setquestion`, `/recovery setanswer`, `/recover`
- **Recovery via 2FA** — when 2FA is enabled, recovery uses TOTP code instead of questions
- **Reconnect grace** — session restoring within configurable window
- **Two-Factor Authentication (2FA)** — TOTP (Google Authenticator compatible)
  - Browser-based setup with QR code and backup codes (single clickable link)
  - CLI fallback (manual secret entry when web server is disabled)
  - Backup codes (BCrypt-hashed, single-use)
  - Rate-limited verification attempts
  - **Smart IP-based skip** — optionally skip 2FA when IP matches last verified IP
  - **Random challenge** — configurable 1-in-N chance to require 2FA even on same IP
  - **Max trusted session** — force 2FA after configurable hours even on same IP
- **Policy enforcement** — require 2FA for OPs and privileged accounts
- **Public API** — `ServerAuthApi` via `ServicesManager` for other plugins
- **i18n** — English (en_US, default) + Portuguese (pt_PT)
- **Async DB** — all database operations run off the main thread
- **Storage** — SQLite (default) or MySQL with automatic schema migrations

---

## Quick Start

1. Drop `ServerAUTH-1.0-SNAPSHOT.jar` into your `plugins/` folder
2. Start the server — default config + SQLite DB will be created
3. Players can `/register <password> <password>` and `/login <password>`
4. Configure `plugins/ServerAUTH/config.yml` as needed

---

## Commands

| Command | Description |
|---------|-------------|
| `/register <pw> <pw>` | Create an account |
| `/login <pw>` | Log in |
| `/changepassword <old> <new> <confirm>` | Change password |
| `/logout` | Log out |
| `/autologin <on\|off\|status>` | Trusted IP auto-login |
| `/recovery <setquestion\|setanswer\|status>` | Recovery setup |
| `/recover` | Recover account with recovery answer |
| `/2fa setup` | Start 2FA setup (sends browser link) |
| `/2fa confirm <code>` | Confirm 2FA setup with a code from your app |
| `/2fa code <code>` | Verify 2FA during login |
| `/2fa status` | Check 2FA status |
| `/2fa disable <code>` | Disable 2FA (requires valid TOTP code) |
| `/authadmin <sub> <player> [args]` | Admin commands (OP only, requires admin's 2FA) |
| `/authhelp` | Show contextual help |

---

## Two-Factor Authentication (2FA)

### Player Guide: Setting Up 2FA

1. Log in normally with `/login <password>`
2. Run `/2fa setup`
3. A **single clickable link** opens in your browser with:
   - A QR code to scan with Google Authenticator / Authy / etc.
   - Your secret key (click to copy)
   - A form to enter and verify a 6-digit code
4. Scan the QR code, enter the code in the browser, and click **Verify & Enable**
5. **Save your backup codes** shown on the success page — they can't be recovered later!
6. If the web server is disabled, you'll get the secret key in chat and use `/2fa confirm <code>`

### Player Guide: Logging In with 2FA

1. `/login <password>` — you'll be told "2FA verification required"
2. `/2fa code <6-digit code>` — enter the current code from your authenticator app
3. You can also use a backup code: `/2fa code ABCD1234`

> **Note:** If `require-only-on-ip-change` is enabled in the server config, 2FA may be skipped
> when logging in from the same IP as your last successful 2FA verification.

### Player Guide: Disabling 2FA

1. While fully authenticated: `/2fa disable <6-digit code>`
2. Requires a valid current TOTP code

### Player Guide: Account Recovery with 2FA

When 2FA is enabled, account recovery uses your TOTP code instead of recovery questions:
1. `/recover` — shows instructions
2. `/recover 2fa <6-digit code>` — verify your identity with a TOTP code
3. `/recover setpassword <new> <confirm>` — set a new password

### Player Guide: Account Recovery without 2FA

If you don't have 2FA and you set up recovery questions:
1. `/recover` — shows your recovery question
2. `/recover answer <your answer>` — verify your identity
3. `/recover setpassword <new> <confirm>` — set a new password

---

## Admin Guide

### Configuration (`config.yml`)

```yaml
two-factor:
  enabled: true                    # Master switch for 2FA
  backup-code-count: 8            # Backup codes per setup
  max-verify-attempts: 5          # Before lockout
  verify-lockout-seconds: 300     # Lockout duration
  setup-token-expiry-minutes: 5   # Web setup token lifetime

  # Smart 2FA prompting (IP-based skip)
  require-only-on-ip-change: false    # Only require 2FA when IP changes
  same-ip-random-challenge:
    enabled: false                     # 1-in-N random 2FA even on same IP
    one-in-n: 10                       # Average frequency
  max-trusted-session-hours: 0         # Force 2FA after N hours (0=disabled)
  debug-skip-messages: false           # Log when 2FA is skipped (for testing)

policy:
  require-2fa-for-ops: true       # OPs must have 2FA

web-server:
  enabled: true                   # Built-in HTTP server
  port: 8921                      # Listen port
  host: "0.0.0.0"                # Bind address
  public-url: "http://your-server-ip:8921"  # URL shown to players
```

### Console Security: Command Redaction

ServerAUTH **automatically redacts sensitive commands** from console logs. When a player types a command containing a password, 2FA code, or recovery answer, the plugin:

1. **Cancels** the command event before the server can log it
2. **Dispatches** the command internally to the correct handler
3. **Logs** a safe redacted version: `Player used /login [REDACTED]`

This applies to: `/login`, `/register`, `/changepassword`, `/2fa code`, `/2fa verify`, `/2fa confirm`, `/2fa disable`, `/recover answer`, `/recover 2fa`, `/recover setpassword`, `/recovery setanswer`.

No configuration is needed — this is always active.

### 2FA Smart Prompting

When `require-only-on-ip-change: true`, the plugin stores the player's IP after each successful 2FA verification. On subsequent logins from the same IP, 2FA is skipped for a smoother experience.

**Safety mechanisms:**
- `same-ip-random-challenge`: Occasionally require 2FA even on the same IP (e.g., 1 in 10 logins)
- `max-trusted-session-hours`: Force 2FA after a time limit, regardless of IP match
- Both use `SecureRandom` and are per-player to prevent gaming

### Web Server

The plugin includes a **minimal built-in HTTP server** (JDK `com.sun.net.httpserver`) for the 2FA setup page. No external dependencies or frameworks.

**Important:** Set `web-server.public-url` to your server's public IP or domain so players can access the setup page.

If you don't want the built-in web server, set `web-server.enabled: false`. Players will still get the manual secret key and otpauth URI in chat.

### Policy: Require 2FA for OPs

When `policy.require-2fa-for-ops: true` (default):
- After an OP logs in with their password, they remain in a "2FA pending" lockdown state
- They must run `/2fa setup` and complete setup before they can play
- This also applies to any player with `two_factor_required = true` in the database

### Admin Commands (`/authadmin`)

OP-only commands for managing other players' auth data. **Every destructive operation requires the admin's own 2FA code** for security.

| Command | Description |
|---------|-------------|
| `/authadmin lookup <player>` | View a player's account info (registered, 2FA status, recovery, last IP) |
| `/authadmin setpassword <player> <newpw> <your-2fa>` | Change a player's password (requires your 2FA code) |
| `/authadmin delete <player> <your-2fa>` | Delete a player's account entirely (requires your 2FA code) |
| `/authadmin reset2fa <player> <your-2fa>` | Reset a player's 2FA (requires your 2FA code) |

**Requirements:**
- The admin must be fully authenticated (logged in + 2FA verified)
- The admin must have 2FA enabled on their own account
- Permission: `serverauth.admin` (default: OP only)

When an admin changes a player's password, deletes their account, or resets their 2FA:
- The target player is automatically logged out
- The target player receives a notification message

---

## Public API (for Plugin Developers)

ServerAUTH registers a `ServerAuthApi` service that other plugins can use.

### Getting the API

```java
import pt.henrique.serverauth.api.ServerAuthApi;

ServerAuthApi api = Bukkit.getServicesManager().load(ServerAuthApi.class);
if (api == null) {
    // ServerAUTH not installed
    return;
}
```

### API Methods

```java
boolean isRegistered(UUID playerId);
boolean isPasswordAuthenticated(UUID playerId);   // password OK (may be pending 2FA)
boolean isFullyAuthenticated(UUID playerId);       // password + 2FA verified
boolean is2faEnabled(UUID playerId);
boolean is2faRequired(UUID playerId);              // policy flag
void set2faRequired(UUID playerId, boolean required);
void forceLogout(UUID playerId, String reason);
OptionalLong getLast2faSuccessMillis(UUID playerId);
int getRemainingLockoutSeconds(UUID playerId);
```

### Events

| Event | When |
|-------|------|
| `PlayerAuthSuccessEvent` | Password verified (before 2FA) |
| `Player2FAPendingEvent` | Player needs 2FA verification |
| `Player2FASuccessEvent` | 2FA code verified |
| `PlayerFullyAuthenticatedEvent` | Fully authenticated (password + 2FA) |
| `Player2FAStateChangeEvent` | 2FA enabled or disabled |

### Example: ServerRoles Integration

```java
// In ServerRoles, when assigning an operator-like role:
ServerAuthApi api = Bukkit.getServicesManager().load(ServerAuthApi.class);
if (api != null) {
    // Mark this player as requiring 2FA
    api.set2faRequired(player.getUniqueId(), true);

    // Check if they have 2FA before granting privileges
    if (!api.is2faEnabled(player.getUniqueId())) {
        player.sendMessage("§cYou must enable 2FA before receiving this role.");
        api.forceLogout(player.getUniqueId(), "§c2FA required for privileged roles.");
        return;
    }
}
```

### Example: Blocking Privilege Elevation

```java
@EventHandler
public void onFullyAuth(PlayerFullyAuthenticatedEvent event) {
    Player p = event.getPlayer();
    ServerAuthApi api = Bukkit.getServicesManager().load(ServerAuthApi.class);
    if (api != null && api.is2faRequired(p.getUniqueId()) && !api.is2faEnabled(p.getUniqueId())) {
        // Force logout — they need to set up 2FA first
        api.forceLogout(p.getUniqueId(), "§cYour role requires 2FA. Use /2fa setup.");
    }
}
```

---

## Database Schema

### Storage Backends

- **SQLite** (default) — `plugins/ServerAUTH/auth.db`
- **MySQL** — configure in `config.yml`

### Migrations

Schema versioning is automatic. The plugin tracks versions in `auth_meta`:
- **V1**: Base `auth_users` table (registration, login, autologin, recovery)
- **V2**: 2FA columns (`two_factor_enabled`, `totp_secret`, `backup_codes_json`, `last_two_factor_success`, `two_factor_attempts`, `two_factor_lockout_until`, `two_factor_required`)
- **V3**: IP-based 2FA skip (`last_2fa_verified_ip`)

---

## Security Notes

- **Console log redaction** — all sensitive commands (passwords, 2FA codes, recovery answers) are intercepted and redacted before the server can log them. Only `Player used /login [REDACTED]` appears in logs.
- **Passwords** — BCrypt hashed (configurable cost, default 12)
- **Recovery answers** — BCrypt hashed
- **TOTP secrets** — stored in database (consider disk encryption for production)
- **Backup codes** — BCrypt hashed individually, stored as JSON array
- **Setup tokens** — cryptographically random, time-limited (5 min default), single-use
- **Rate limiting** — separate lockout for login attempts and 2FA attempts
- **No debug leaks** — secrets, tokens, and codes are never printed to server logs, even in debug mode
- **TOTP window** — ±1 time step drift allowed (window size 3)
- **Web server** — minimal surface area, no frameworks, security headers set
- **IP-based skip** — uses `SecureRandom` for random challenges; last verified IP stored in DB (not secrets)

---

## Localization

Language files are in `plugins/ServerAUTH/lang/` (auto-extracted from JAR).

- `en_US.yml` — English (default)
- `pt_PT.yml` — Portuguese

Override by placing a modified copy in `plugins/ServerAUTH/lang/`.

---

## Building

```bash
mvn clean package
```

Requires Java 21. The shaded JAR will be at `target/ServerAUTH-1.0-SNAPSHOT.jar`.

---

## License

Copyright © Henrique. All rights reserved.
