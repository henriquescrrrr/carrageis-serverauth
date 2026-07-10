# ServerAUTH Feature Summary

## Coordinate Hiding During Login

**Config (`config.yml`):**
```yaml
lockdown:
  hide-coordinates-during-login: true
  login-spawn-location: "world,0,0,0,0,0"
```

**How it works:**
- On join, the player's real location is saved in memory + DB, then they're teleported to the login spawn.
- After full authentication (login, 2FA, grace, autologin, register), they're teleported back to their real location.
- DB persistence means real locations survive server restarts.

## Admin Reload

**Usage:** `/authadmin reload`
- Reloads `config.yml` and language files from disk.
- Requires `serverauth.admin` permission.
- Works from both in-game and console.

