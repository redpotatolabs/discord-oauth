package discordoauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"golang.org/x/oauth2"
)

// User is the subset of /users/@me consumers need.
type User struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	GlobalName    string `json:"global_name"`
	Discriminator string `json:"discriminator"`
	Avatar        string `json:"avatar"`
}

// DisplayName returns the user-facing label: GlobalName when present,
// otherwise Username#Discriminator (legacy) or just Username (new
// discriminator-less system; Discord sends "0" or empty for those).
func (u *User) DisplayName() string {
	if u == nil {
		return ""
	}
	if u.GlobalName != "" {
		return u.GlobalName
	}
	if u.Discriminator != "" && u.Discriminator != "0" {
		return fmt.Sprintf("%s#%s", u.Username, u.Discriminator)
	}
	return u.Username
}

// Guild is the subset of /users/@me/guilds consumers need.
type Guild struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Icon        string         `json:"icon"`
	Owner       bool           `json:"owner"`
	Permissions PermissionsInt `json:"permissions"`
}

// HasAdministrator returns true when the user is the guild owner or holds
// the Administrator permission bit.
func (g Guild) HasAdministrator() bool {
	return g.Owner || g.Permissions.Has(PermissionAdministrator)
}

// HasManageServer returns true when the user is the guild owner, holds
// Administrator, or holds Manage Server.
func (g Guild) HasManageServer() bool {
	return g.Owner || g.Permissions.Has(PermissionAdministrator) || g.Permissions.Has(PermissionManageServer)
}

// HasManageRoles returns true when the user is the guild owner, holds
// Administrator, or holds Manage Roles.
func (g Guild) HasManageRoles() bool {
	return g.Owner || g.Permissions.Has(PermissionAdministrator) || g.Permissions.Has(PermissionManageRoles)
}

// PermissionsInt accepts Discord's permission bitmask as either a JSON
// number or a JSON string of digits — the wire format varies by API
// version and endpoint.
type PermissionsInt int64

// Has reports whether the bitmask contains every bit in `bits`. Use the
// PermissionXxx constants for `bits`.
func (p PermissionsInt) Has(bits int64) bool {
	return int64(p)&bits == bits
}

// UnmarshalJSON accepts both number and string forms.
func (p *PermissionsInt) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return err
		}
		*p = PermissionsInt(n)
		return nil
	}
	var n int64
	if err := json.Unmarshal(data, &n); err != nil {
		return err
	}
	*p = PermissionsInt(n)
	return nil
}

// FetchUser calls GET /users/@me. Returns an error when Discord rejects
// the token, the network call fails, or the response body is unparseable.
func (c *Client) FetchUser(ctx context.Context, token *oauth2.Token) (*User, error) {
	var u User
	if err := c.fetchJSON(ctx, token, discordAPIBase+"/users/@me", &u); err != nil {
		return nil, err
	}
	if u.ID == "" {
		return nil, errors.New("discord-oauth: empty user id from /users/@me")
	}
	return &u, nil
}

// FetchUserGuilds calls GET /users/@me/guilds. The slice is in Discord's
// returned order (membership order, roughly join time).
func (c *Client) FetchUserGuilds(ctx context.Context, token *oauth2.Token) ([]Guild, error) {
	var guilds []Guild
	if err := c.fetchJSON(ctx, token, discordAPIBase+"/users/@me/guilds", &guilds); err != nil {
		return nil, err
	}
	return guilds, nil
}

func (c *Client) fetchJSON(ctx context.Context, token *oauth2.Token, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("discord-oauth: %s returned %d: %s", url, resp.StatusCode, string(body))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
