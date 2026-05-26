// Package discordoauth provides Discord OAuth2 + user-context REST helpers
// shared across epistemi web services (nagbot, tater, roster). It owns
// only the OAuth flow and the /users/@me + /users/@me/guilds calls —
// session storage, CSRF, routing, and bot-token REST are intentionally
// left to consumers.
//
// Typical use:
//
//	c := discordoauth.New(discordoauth.Config{
//	    ClientID:     cfg.ClientID,
//	    ClientSecret: cfg.OAuthClientSecret,
//	    PublicURL:    cfg.PublicURL,
//	})
//	// login handler:
//	http.Redirect(w, r, c.AuthCodeURL(state), http.StatusFound)
//	// callback handler:
//	tok, err := c.Exchange(ctx, code)
//	user, err := c.FetchUser(ctx, tok)
//	guilds, err := c.FetchUserGuilds(ctx, tok)
package discordoauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// CallbackPath is the path component of the OAuth redirect; consumers
// mount their callback handler at this path. Constant by design — every
// epistemi consumer uses /auth/callback.
const CallbackPath = "/auth/callback"

// Scope constants for clarity at the call site.
const (
	ScopeIdentify = "identify"
	ScopeGuilds   = "guilds"
)

// Discord permission bits we care about for admin gating. The full list
// is at <https://discord.com/developers/docs/topics/permissions>.
const (
	PermissionAdministrator int64 = 0x8
	PermissionManageServer  int64 = 0x20
	PermissionManageRoles   int64 = 0x10000000
)

// discordOAuthEndpoint is overridable in tests via package-level vars
// below; consumers should not reach for it.
var discordOAuthEndpoint = oauth2.Endpoint{
	AuthURL:   "https://discord.com/api/oauth2/authorize",
	TokenURL:  "https://discord.com/api/oauth2/token",
	AuthStyle: oauth2.AuthStyleInParams,
}

// discordAPIBase is overridable in tests.
var discordAPIBase = "https://discord.com/api/v10"

// Config bundles per-app OAuth settings.
type Config struct {
	// ClientID is the Discord application ID. Required.
	ClientID string
	// ClientSecret is the Discord OAuth client secret. Required.
	ClientSecret string
	// PublicURL is the canonical public URL of the app (e.g.
	// "https://nagbot.klinke.wtf"). The redirect URI is built as
	// PublicURL + CallbackPath. Required unless RedirectURL is set.
	PublicURL string
	// RedirectURL, when non-empty, is used verbatim as the OAuth redirect
	// URI instead of PublicURL + CallbackPath. For consumers (like roster)
	// that store a full redirect URL in their own settings. When set,
	// PublicURL becomes optional.
	RedirectURL string
	// Scopes defaults to {"identify", "guilds"} when nil/empty.
	Scopes []string
	// HTTPClient defaults to &http.Client{Timeout: 15*time.Second} when
	// nil. Use this to inject a test client or share connection pools.
	HTTPClient *http.Client
}

// Client is the per-app OAuth client. Goroutine-safe.
type Client struct {
	config     *oauth2.Config
	httpClient *http.Client
	publicURL  string
}

// New creates a client from cfg. Returns an error when ClientID,
// ClientSecret, or PublicURL is empty.
func New(cfg Config) (*Client, error) {
	if cfg.ClientID == "" {
		return nil, errors.New("discord-oauth: Config.ClientID is required")
	}
	if cfg.ClientSecret == "" {
		return nil, errors.New("discord-oauth: Config.ClientSecret is required")
	}
	if cfg.PublicURL == "" && cfg.RedirectURL == "" {
		return nil, errors.New("discord-oauth: Config.PublicURL or Config.RedirectURL is required")
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{ScopeIdentify, ScopeGuilds}
	}
	publicURL := strings.TrimRight(cfg.PublicURL, "/")
	redirectURL := cfg.RedirectURL
	if redirectURL == "" {
		redirectURL = publicURL + CallbackPath
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{
		config: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     discordOAuthEndpoint,
			RedirectURL:  redirectURL,
			Scopes:       scopes,
		},
		httpClient: httpClient,
		publicURL:  publicURL,
	}, nil
}

// RedirectURL is the absolute URL Discord redirects back to after sign-in.
// Consumers register this in the Discord developer portal under OAuth2 →
// Redirect URIs.
func (c *Client) RedirectURL() string { return c.config.RedirectURL }

// AuthCodeURL builds the Discord OAuth authorize URL. The state should be
// a random value the caller stores in a short-lived cookie and verifies
// on callback.
func (c *Client) AuthCodeURL(state string) string {
	return c.config.AuthCodeURL(state)
}

// Exchange swaps an authorization code for an access token. Pass the
// `code` value Discord sent to the callback URL.
func (c *Client) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return c.config.Exchange(ctx, code)
}
