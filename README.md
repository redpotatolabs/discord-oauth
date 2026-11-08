# discord-oauth

Discord OAuth2 + user-context REST helpers for redpotatolabs Go services (nagbot, tater, roster).

This module owns the OAuth flow (`AuthCodeURL`, `Exchange`) plus the user-context REST calls (`/users/@me`, `/users/@me/guilds`). It does **not** own:

- Session storage — apps store the returned `*oauth2.Token` however they want. `Refresh` renews an expired one, and apps save the result.
- CSRF — apps issue + verify their own tokens.
- HTTP routing — apps wire login + callback handlers themselves.
- Bot-token calls (`FetchBotGuilds`, `FetchGuildRoles`, etc.) — those stay per-app because the behaviors diverge (roster caches with TTL + stale-on-rate-limit; tater/nagbot read from in-memory discordgo state).

See [`/home/roy/private/repos/discord-oauth-api.md`](https://github.com/redpotatolabs/discord-oauth/blob/main/discord-oauth-api.md) (in the planning tree) for the full design rationale.

## Install

```bash
go get github.com/redpotatolabs/discord-oauth@latest
```

## Use

```go
import "github.com/redpotatolabs/discord-oauth"

c, err := discordoauth.New(discordoauth.Config{
    ClientID:     cfg.ClientID,
    ClientSecret: cfg.OAuthClientSecret,
    PublicURL:    cfg.PublicURL,    // e.g. "https://nagbot.klinke.wtf"
})

// login handler:
http.Redirect(w, r, c.AuthCodeURL(state), http.StatusFound)

// callback handler:
tok, err := c.Exchange(ctx, r.URL.Query().Get("code"))
user, err := c.FetchUser(ctx, tok)
guilds, err := c.FetchUserGuilds(ctx, tok)

for _, g := range guilds {
    if g.HasManageServer() {
        // ...
    }
}
```

Register `<PublicURL>/auth/callback` in the Discord developer portal under **OAuth2 → Redirect URIs**.

## What ships

| Symbol | Purpose |
| --- | --- |
| `Config`, `New` | construct a per-app `*Client` |
| `Client.AuthCodeURL(state)` | build the Discord authorize URL |
| `Client.RedirectURL()` | the absolute callback URL (register with Discord) |
| `Client.Exchange(ctx, code)` | swap an authorization code for a token |
| `Client.FetchUser(ctx, tok)` | GET `/users/@me` |
| `Client.FetchUserGuilds(ctx, tok)` | GET `/users/@me/guilds` |
| `User`, `User.DisplayName()` | user struct + display-name helper (handles legacy + new discriminators) |
| `Guild` | guild struct with bitmask permissions |
| `Guild.HasAdministrator/HasManageServer/HasManageRoles` | permission checks; owner short-circuits |
| `PermissionsInt` | Discord-bitmask type that accepts JSON number *or* string |
| `PermissionAdministrator`, `PermissionManageServer`, `PermissionManageRoles` | bit constants |
| `CallbackPath` (constant `/auth/callback`) | mount path consumers use for their callback handler |

## What doesn't ship

This is intentional:

- **Session storage.** Apps decide whether to hold tokens in memory, encrypt + persist, or swap for an internal session ID. The library returns `*oauth2.Token`; what you do with it is yours.
- **CSRF tokens.** Apps generate + verify their own.
- **Permission bits the library doesn't already use.** If you need `PermissionManageChannels` or others, add them to your own code; we surface the three that all current consumers gate on.
- **Bot-token REST.** `FetchBotGuilds`, `FetchGuildRoles`, `FetchGuildMembers` — these use the bot token (not user token), and behaviors diverge per consumer (roster caches with TTL + stale-on-rate-limit; tater/nagbot read live from discordgo state). They stay in each consumer.
