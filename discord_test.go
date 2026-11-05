package discordoauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestPermissionsInt_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want int64
	}{
		{"number", `1234567`, 1234567},
		{"string", `"1234567"`, 1234567},
		{"zero number", `0`, 0},
		{"zero string", `"0"`, 0},
		{"admin bit", `"8"`, 8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p PermissionsInt
			if err := json.Unmarshal([]byte(tt.raw), &p); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if int64(p) != tt.want {
				t.Fatalf("got %d, want %d", int64(p), tt.want)
			}
		})
	}
}

func TestPermissionsInt_UnmarshalJSON_Errors(t *testing.T) {
	var p PermissionsInt
	if err := json.Unmarshal([]byte(`"not-a-number"`), &p); err == nil {
		t.Fatal("expected error on non-numeric string")
	}
}

func TestGuildPermissionChecks(t *testing.T) {
	owner := Guild{Owner: true}
	admin := Guild{Permissions: PermissionsInt(PermissionAdministrator)}
	manager := Guild{Permissions: PermissionsInt(PermissionManageServer)}
	none := Guild{Permissions: PermissionsInt(0x1)}

	for _, tc := range []struct {
		name string
		g    Guild
		want struct{ admin, server, roles bool }
	}{
		{"owner gets everything", owner, struct{ admin, server, roles bool }{true, true, true}},
		{"admin bit grants all", admin, struct{ admin, server, roles bool }{true, true, true}},
		{"manage server only", manager, struct{ admin, server, roles bool }{false, true, false}},
		{"random low bit grants none", none, struct{ admin, server, roles bool }{false, false, false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.g.HasAdministrator(); got != tc.want.admin {
				t.Errorf("HasAdministrator: got %v, want %v", got, tc.want.admin)
			}
			if got := tc.g.HasManageServer(); got != tc.want.server {
				t.Errorf("HasManageServer: got %v, want %v", got, tc.want.server)
			}
			if got := tc.g.HasManageRoles(); got != tc.want.roles {
				t.Errorf("HasManageRoles: got %v, want %v", got, tc.want.roles)
			}
		})
	}
}

func TestUser_DisplayName(t *testing.T) {
	cases := []struct {
		u    User
		want string
	}{
		{User{Username: "alice", GlobalName: "Alice A."}, "Alice A."},
		{User{Username: "bob", Discriminator: "1234"}, "bob#1234"},
		{User{Username: "carol", Discriminator: "0"}, "carol"},
		{User{Username: "dave"}, "dave"},
	}
	for _, tc := range cases {
		if got := tc.u.DisplayName(); got != tc.want {
			t.Errorf("%+v: got %q, want %q", tc.u, got, tc.want)
		}
	}
}

func TestFetchUser_AgainstStub(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/users/@me" {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			http.Error(w, "wrong auth: "+got, http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"id":"u1","username":"alice","global_name":"Alice A."}`))
	}))
	defer srv.Close()

	prevBase := discordAPIBase
	discordAPIBase = srv.URL
	defer func() { discordAPIBase = prevBase }()

	c, err := New(Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		PublicURL:    "https://example.com",
		HTTPClient:   &http.Client{Timeout: 5 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	u, err := c.FetchUser(context.Background(), &oauth2.Token{AccessToken: "test-token"})
	if err != nil {
		t.Fatalf("FetchUser: %v", err)
	}
	if u.ID != "u1" || u.DisplayName() != "Alice A." {
		t.Errorf("unexpected user: %+v", u)
	}
}

func TestFetchUserGuilds_AgainstStub(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/users/@me/guilds" {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		// Mix of number and string permission encodings to exercise
		// PermissionsInt.UnmarshalJSON.
		_, _ = w.Write([]byte(`[
			{"id":"g1","name":"One","owner":true,"permissions":"0"},
			{"id":"g2","name":"Two","owner":false,"permissions":32}
		]`))
	}))
	defer srv.Close()

	prevBase := discordAPIBase
	discordAPIBase = srv.URL
	defer func() { discordAPIBase = prevBase }()

	c, _ := New(Config{ClientID: "cid", ClientSecret: "csec", PublicURL: "https://example.com"})
	guilds, err := c.FetchUserGuilds(context.Background(), &oauth2.Token{AccessToken: "tok"})
	if err != nil {
		t.Fatalf("FetchUserGuilds: %v", err)
	}
	if len(guilds) != 2 {
		t.Fatalf("expected 2 guilds, got %d", len(guilds))
	}
	if !guilds[0].HasManageServer() {
		t.Errorf("guild 0 (owner) should have manage server")
	}
	if !guilds[1].HasManageServer() {
		t.Errorf("guild 1 (bit 0x20) should have manage server")
	}
}

func TestAuthCodeURL_ContainsState(t *testing.T) {
	c, err := New(Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		PublicURL:    "https://example.com/",
	})
	if err != nil {
		t.Fatal(err)
	}
	url := c.AuthCodeURL("xyz")
	if !contains(url, "state=xyz") {
		t.Errorf("AuthCodeURL missing state: %s", url)
	}
	if c.RedirectURL() != "https://example.com/auth/callback" {
		t.Errorf("RedirectURL: %s", c.RedirectURL())
	}
}

func TestNew_RejectsEmpty(t *testing.T) {
	cases := []Config{
		{},
		{ClientID: "cid"},
		{ClientID: "cid", ClientSecret: "csec"},
	}
	for _, cfg := range cases {
		if _, err := New(cfg); err == nil {
			t.Errorf("expected error for %+v", cfg)
		}
	}
}

func TestNew_RedirectURLOverride(t *testing.T) {
	// RedirectURL satisfies the "PublicURL or RedirectURL required" rule
	// and is used verbatim.
	c, err := New(Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		RedirectURL:  "https://app.example.com/oauth/cb",
	})
	if err != nil {
		t.Fatalf("New with RedirectURL: %v", err)
	}
	if c.RedirectURL() != "https://app.example.com/oauth/cb" {
		t.Errorf("RedirectURL = %q", c.RedirectURL())
	}
}

func TestFetchGuildMemberRoles_AgainstStub(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/users/@me/guilds/g1/member" {
			http.Error(w, "wrong path: "+r.URL.Path, http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"roles":["r1","r2","r3"]}`))
	}))
	defer srv.Close()

	prevBase := discordAPIBase
	discordAPIBase = srv.URL
	defer func() { discordAPIBase = prevBase }()

	roles, err := FetchGuildMemberRoles(context.Background(), srv.Client(), &oauth2.Token{AccessToken: "tok"}, "g1")
	if err != nil {
		t.Fatalf("FetchGuildMemberRoles: %v", err)
	}
	if len(roles) != 3 || roles[0] != "r1" {
		t.Errorf("roles = %v", roles)
	}
}

func TestPackageFetchUser_TokenOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"u9","username":"zoe"}`))
	}))
	defer srv.Close()
	prevBase := discordAPIBase
	discordAPIBase = srv.URL
	defer func() { discordAPIBase = prevBase }()

	// No Client construction — just an http.Client + token.
	u, err := FetchUser(context.Background(), srv.Client(), &oauth2.Token{AccessToken: "tok"})
	if err != nil {
		t.Fatalf("FetchUser: %v", err)
	}
	if u.ID != "u9" {
		t.Errorf("user = %+v", u)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func refreshClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := New(Config{ClientID: "id", ClientSecret: "secret", PublicURL: "https://example.test"})
	if err != nil {
		t.Fatal(err)
	}
	c.config.Endpoint = oauth2.Endpoint{TokenURL: srv.URL, AuthStyle: oauth2.AuthStyleInParams}
	return c
}

func TestRefreshKeepsAValidToken(t *testing.T) {
	c := refreshClient(t, func(w http.ResponseWriter, _ *http.Request) {
		t.Error("a valid token should not be refreshed")
	})
	token := &oauth2.Token{AccessToken: "a", RefreshToken: "r", Expiry: time.Now().Add(time.Hour)}
	got, err := c.Refresh(context.Background(), token)
	if err != nil || got != token {
		t.Errorf("got %+v, err %v", got, err)
	}
}

func TestRefreshRenewsAnExpiredToken(t *testing.T) {
	c := refreshClient(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.PostForm.Get("grant_type") != "refresh_token" || r.PostForm.Get("refresh_token") != "old-refresh" {
			t.Errorf("form = %v", r.PostForm)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new","refresh_token":"new-refresh","token_type":"Bearer","expires_in":604800}`))
	})
	got, err := c.Refresh(context.Background(), &oauth2.Token{AccessToken: "old", RefreshToken: "old-refresh", Expiry: time.Now().Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != "new" || got.RefreshToken != "new-refresh" || !got.Valid() {
		t.Errorf("got %+v", got)
	}
}

func TestRefreshSaysWhenSigningInIsNeeded(t *testing.T) {
	expired := func(refresh string) *oauth2.Token {
		return &oauth2.Token{AccessToken: "old", RefreshToken: refresh, Expiry: time.Now().Add(-time.Hour)}
	}
	denied := refreshClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	})
	if _, err := denied.Refresh(context.Background(), expired("revoked")); !errors.Is(err, ErrSignInAgain) {
		t.Errorf("revoked: %v", err)
	}
	if _, err := denied.Refresh(context.Background(), expired("")); !errors.Is(err, ErrSignInAgain) {
		t.Errorf("no refresh token: %v", err)
	}
	down := refreshClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	if _, err := down.Refresh(context.Background(), expired("r")); err == nil || errors.Is(err, ErrSignInAgain) {
		t.Errorf("an outage is temporary: %v", err)
	}
}
