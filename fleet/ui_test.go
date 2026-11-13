package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fake env-gen: only the vault subcommands fleet uses. It insists on BW_SESSION=SESS,
// which proves the UI hands its in-memory session to env-gen.
const fakeEnvGen = `#!/usr/bin/env bash
v="$FAKE_VAULT"; mkdir -p "$v"
if [[ "$1 $2" == "vault unlock" ]]; then
  read -r pw; [[ "$pw" == "pw" ]] && { echo SESS; exit 0; } || { echo "Invalid master password." >&2; exit 1; }
fi
[[ "$BW_SESSION" == "SESS" ]] || { echo "vault locked" >&2; exit 1; }
case "$1 $2" in
 "vault get") [[ -f "$v/$3" ]] && cat "$v/$3" || { echo "not found" >&2; exit 3; } ;;
 "vault set") item="${@: -1}"; python3 -c '
import sys,json,os
p=sys.argv[1]; cur=json.load(open(p)) if os.path.exists(p) else {}
cur.update(json.load(sys.stdin)); json.dump(cur,open(p,"w"))' "$v/$item" ;;
 "keys rm") shift 3; item="$1"; shift; python3 -c '
import sys,json
p=sys.argv[1]; cur=json.load(open(p))
for k in sys.argv[2:]: cur.pop(k,None)
json.dump(cur,open(p,"w"))' "$v/$item" "$@" ;;
esac
`

type fleetUI struct {
	s      *uiServer
	srv    *httptest.Server
	client *http.Client
	dir    string
	vault  string
	editor []byte
	adm    []byte
	csrf   string
}

func newFleetUI(t *testing.T) *fleetUI {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "env-gen")
	os.WriteFile(bin, []byte(fakeEnvGen), 0o755)
	vault := filepath.Join(dir, "vault")
	os.MkdirAll(vault, 0o755)
	os.WriteFile(filepath.Join(vault, "shop"), []byte(`{"A":"1","DB_PASSWORD":"s3cret","LOCAL_ONLY":"x"}`), 0o600)
	os.WriteFile(filepath.Join(vault, "shop-prod"), []byte(`{"A":"prod","DB_PASSWORD":"prodpw"}`), 0o600)
	os.WriteFile(filepath.Join(vault, "unrelated"), []byte(`{"TOP":"secret"}`), 0o600)
	os.MkdirAll(filepath.Join(dir, "laptop"), 0o755)
	os.MkdirAll(filepath.Join(dir, "prod"), 0o755)
	os.WriteFile(filepath.Join(dir, "laptop", ".env"), []byte("A=old\nEXTRA=keep\n"), 0o600)
	cfgPath := filepath.Join(dir, "apps.yaml")
	os.WriteFile(cfgPath, []byte(`apps:
  shop:
    vault_item: shop
    exclude: [LOCAL_ONLY]
    targets:
      laptop:
        driver: file
        file: `+filepath.Join(dir, "laptop", ".env")+`
      prod:
        driver: file
        file: `+filepath.Join(dir, "prod", ".env")+`
        vault_item: shop-prod
        overrides: { APP_ENV: production }
        reload: echo reloaded > `+filepath.Join(dir, "reloaded")+`
`), 0o644)
	t.Setenv("FAKE_VAULT", vault)
	editor, adm := []byte("12345678901234567890"), []byte("abcdefghijklmnopqrst")
	salt := []byte("saltsaltsaltsalt")
	key, _ := hashPassphrase("correct horse battery", salt, 1000)
	s := &uiServer{cfgPath: cfgPath, insecure: true, idle: time.Minute, maxAge: time.Hour, envgen: bin, jobs: 2,
		creds:    &uiCreds{totp: editor, adminSalt: salt, adminKey: key, adminIter: 1000, adminTOTP: adm},
		adminTTL: 5 * time.Minute, hosts: map[string]bool{}, lim: newLimiter(), adminLim: newLimiter()}
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return &fleetUI{s: s, srv: srv, client: &http.Client{Jar: jar}, dir: dir, vault: vault, editor: editor, adm: adm}
}

func (e *fleetUI) do(t *testing.T, method, path string, body any) (int, map[string]any, string) {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	if method != "GET" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-CSRF-Token", e.csrf)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var raw bytes.Buffer
	raw.ReadFrom(resp.Body)
	var out map[string]any
	json.Unmarshal(raw.Bytes(), &out)
	return resp.StatusCode, out, raw.String()
}

func (e *fleetUI) login(t *testing.T) {
	t.Helper()
	e.s.mu.Lock()
	e.s.lastTOTP = 0
	e.s.mu.Unlock()
	st, out, _ := e.do(t, "POST", "/api/login", map[string]string{"password": "pw", "code": totpAt(e.editor, time.Now().Unix()/30)})
	if st != 200 {
		t.Fatalf("login: %d %v", st, out)
	}
	e.csrf = out["csrf"].(string)
}

func (e *fleetUI) elevate(t *testing.T) {
	t.Helper()
	e.s.mu.Lock()
	e.s.lastAdminTOTP = 0
	e.s.mu.Unlock()
	if st, out, _ := e.do(t, "POST", "/api/admin/elevate", map[string]string{"passphrase": "correct horse battery", "code": totpAt(e.adm, time.Now().Unix()/30)}); st != 200 {
		t.Fatalf("elevate: %d %v", st, out)
	}
}

func TestFleetUIAuth(t *testing.T) {
	e := newFleetUI(t)
	for _, p := range []string{"/api/apps", "/api/state?app=shop", "/api/vault/vars?item=shop", "/api/admin/value?item=shop&key=A"} {
		if st, _, _ := e.do(t, "GET", p, nil); st != 401 {
			t.Errorf("%s: %d", p, st)
		}
	}
	code := totpAt(e.editor, time.Now().Unix()/30)
	if st, _, _ := e.do(t, "POST", "/api/login", map[string]string{"password": "wrong", "code": code}); st != 401 {
		t.Errorf("wrong master password: %d", st)
	}
	if st, _, _ := e.do(t, "POST", "/api/login", map[string]string{"password": "pw", "code": "000000"}); st != 401 {
		t.Errorf("wrong code: %d", st)
	}
	e.login(t) // the failed attempts above must not have burned the valid code
}

func TestFleetUIReadOnlyShowsNamesOnly(t *testing.T) {
	e := newFleetUI(t)
	e.login(t)
	_, apps, raw := e.do(t, "GET", "/api/apps", nil)
	if !strings.Contains(raw, "laptop") || !strings.Contains(raw, "APP_ENV") {
		t.Fatalf("apps: %v", apps)
	}
	st, _, raw := e.do(t, "GET", "/api/state?app=shop", nil)
	if st != 200 {
		t.Fatalf("state: %d %s", st, raw)
	}
	for _, secret := range []string{"s3cret", "prodpw", "old"} {
		if strings.Contains(raw, secret) {
			t.Fatalf("state leaked a value (%q): %s", secret, raw)
		}
	}
	var res struct {
		Targets []TargetStatus `json:"targets"`
	}
	json.Unmarshal([]byte(raw), &res)
	byName := map[string]TargetStatus{}
	for _, x := range res.Targets {
		byName[x.Target] = x
	}
	l, p := byName["laptop"], byName["prod"]
	if l.State != "drifted" || strings.Join(l.Changed, ",") != "A" || strings.Join(l.Missing, ",") != "DB_PASSWORD" || strings.Join(l.Extra, ",") != "EXTRA" {
		t.Fatalf("laptop: %+v", l)
	}
	if p.State != "missing" || len(p.Missing) != 3 { // A, DB_PASSWORD from shop-prod + APP_ENV override
		t.Fatalf("prod: %+v", p)
	}
	if st, _, _ := e.do(t, "GET", "/api/state?app=nope", nil); st != 404 {
		t.Errorf("unknown app: %d", st)
	}
	// vault listing: names and lengths only, and only items named in apps.yaml
	_, _, raw = e.do(t, "GET", "/api/vault/vars?item=shop", nil)
	if strings.Contains(raw, "s3cret") || !strings.Contains(raw, "DB_PASSWORD") || !strings.Contains(raw, `"length":6`) {
		t.Fatalf("vars: %s", raw)
	}
	if st, _, _ := e.do(t, "GET", "/api/vault/vars?item=unrelated", nil); st != 404 {
		t.Errorf("item outside apps.yaml must be refused: %d", st)
	}
	// pull plan is names only
	_, _, raw = e.do(t, "POST", "/api/pull/plan", map[string]string{"app": "shop", "target": "laptop"})
	if !strings.Contains(raw, "EXTRA") || strings.Contains(raw, "keep") {
		t.Fatalf("pull plan: %s", raw)
	}
}

func TestFleetUIAdminGate(t *testing.T) {
	e := newFleetUI(t)
	e.login(t)
	calls := []struct {
		m, p string
		b    any
	}{
		{"POST", "/api/admin/push", map[string]any{"app": "shop", "targets": []string{"laptop"}}},
		{"POST", "/api/admin/pull", map[string]any{"app": "shop", "target": "laptop"}},
		{"GET", "/api/admin/value?item=shop&key=A", nil},
		{"POST", "/api/admin/set", map[string]any{"item": "shop", "key": "N", "value": "v"}},
		{"POST", "/api/admin/delete", map[string]any{"item": "shop", "keys": []string{"A"}}},
		{"POST", "/api/admin/rename", map[string]any{"item": "shop", "old": "A", "new": "B"}},
	}
	for _, c := range calls {
		if st, _, _ := e.do(t, c.m, c.p, c.b); st != 403 {
			t.Errorf("%s %s without admin: %d", c.m, c.p, st)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(e.dir, "laptop", ".env")); string(b) != "A=old\nEXTRA=keep\n" {
		t.Fatal("a refused push changed the file")
	}
	// the editor's authenticator code must not elevate
	e.s.mu.Lock()
	e.s.lastAdminTOTP = 0
	e.s.mu.Unlock()
	if st, _, _ := e.do(t, "POST", "/api/admin/elevate", map[string]string{"passphrase": "correct horse battery", "code": totpAt(e.editor, time.Now().Unix()/30)}); st != 401 {
		t.Errorf("editor code accepted for admin: %d", st)
	}
}

func TestFleetUIPushPullVault(t *testing.T) {
	e := newFleetUI(t)
	e.login(t)
	e.elevate(t)

	// push to both targets (prod gets reload)
	st, out, raw := e.do(t, "POST", "/api/admin/push", map[string]any{"app": "shop", "targets": []string{"laptop", "prod"}, "reload": true})
	if st != 200 {
		t.Fatalf("push: %d %s", st, raw)
	}
	if strings.Contains(raw, "s3cret") || strings.Contains(raw, "prodpw") {
		t.Fatalf("push response leaked values: %s", raw)
	}
	_ = out
	lap, _ := os.ReadFile(filepath.Join(e.dir, "laptop", ".env"))
	if string(lap) != "A=1\nEXTRA=keep\nDB_PASSWORD=s3cret\n" {
		t.Fatalf("laptop: %q", lap)
	}
	prod, _ := os.ReadFile(filepath.Join(e.dir, "prod", ".env"))
	for _, want := range []string{"A=prod", "DB_PASSWORD=prodpw", "APP_ENV=production"} {
		if !strings.Contains(string(prod), want) {
			t.Fatalf("prod missing %q: %q", want, prod)
		}
	}
	if _, err := os.Stat(filepath.Join(e.dir, "reloaded")); err != nil {
		t.Fatal("reload command did not run")
	}
	if _, err := os.Stat(filepath.Join(e.dir, "laptop", ".env.bak")); err != nil {
		t.Fatal("no .bak")
	}
	// a second push is a no-op
	_, _, raw = e.do(t, "POST", "/api/admin/push", map[string]any{"app": "shop", "targets": []string{"laptop"}})
	if !strings.Contains(raw, `"unchanged":1`) {
		t.Fatalf("second push: %s", raw)
	}
	if st, _, _ := e.do(t, "POST", "/api/admin/push", map[string]any{"app": "shop", "targets": []string{"nope"}}); st != 404 {
		t.Errorf("unknown target: %d", st)
	}

	// pull a change made on the laptop into the vault
	os.WriteFile(filepath.Join(e.dir, "laptop", ".env"), []byte("A=fromlaptop\nNEWVAR=n\nLOCAL_ONLY=zz\n"), 0o600)
	if st, _, raw := e.do(t, "POST", "/api/admin/pull", map[string]any{"app": "shop", "target": "laptop"}); st != 200 || !strings.Contains(raw, `"stored":2`) {
		t.Fatalf("pull: %d %s", st, raw)
	}
	vb, _ := os.ReadFile(filepath.Join(e.vault, "shop"))
	if !strings.Contains(string(vb), `"A": "fromlaptop"`) && !strings.Contains(string(vb), `"A":"fromlaptop"`) {
		t.Fatalf("vault after pull: %s", vb)
	}
	if strings.Contains(string(vb), "zz") {
		t.Fatalf("excluded key was imported: %s", vb)
	}

	// vault editing
	if _, v, _ := e.do(t, "GET", "/api/admin/value?item=shop&key=A", nil); v["value"] != "fromlaptop" {
		t.Fatalf("reveal: %v", v)
	}
	if st, _, _ := e.do(t, "POST", "/api/admin/set", map[string]any{"item": "shop", "key": "TOKEN", "value": "t0k"}); st != 200 {
		t.Fatalf("set: %d", st)
	}
	if st, _, _ := e.do(t, "POST", "/api/admin/set", map[string]any{"item": "shop", "key": "bad key", "value": "x"}); st != 400 {
		t.Errorf("bad key: %d", st)
	}
	if st, _, _ := e.do(t, "POST", "/api/admin/set", map[string]any{"item": "unrelated", "key": "X", "value": "x"}); st != 404 {
		t.Errorf("item outside apps.yaml: %d", st)
	}
	if st, _, _ := e.do(t, "POST", "/api/admin/rename", map[string]any{"item": "shop", "old": "TOKEN", "new": "API_TOKEN"}); st != 200 {
		t.Fatalf("rename: %d", st)
	}
	if st, _, _ := e.do(t, "POST", "/api/admin/rename", map[string]any{"item": "shop", "old": "API_TOKEN", "new": "A"}); st != 409 {
		t.Errorf("rename onto existing: %d", st)
	}
	if st, _, _ := e.do(t, "POST", "/api/admin/delete", map[string]any{"item": "shop", "keys": []string{"API_TOKEN"}}); st != 200 {
		t.Fatalf("delete: %d", st)
	}
	vb, _ = os.ReadFile(filepath.Join(e.vault, "shop"))
	if strings.Contains(string(vb), "TOKEN") {
		t.Fatalf("variable still in vault: %s", vb)
	}
	if ub, _ := os.ReadFile(filepath.Join(e.vault, "unrelated")); !strings.Contains(string(ub), "secret") {
		t.Fatal("unrelated item was touched")
	}
}

func TestFleetUIGuards(t *testing.T) {
	e := newFleetUI(t)
	e.login(t)
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/logout", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", e.csrf)
	req.Header.Set("Origin", "https://evil.example")
	if resp, _ := e.client.Do(req); resp.StatusCode != 403 {
		t.Errorf("cross-origin: %d", resp.StatusCode)
	}
	if st, _, _ := e.do(t, "POST", "/api/logout", map[string]any{}); st != 200 {
		t.Fatalf("logout: %d", st)
	}
	if st, _, _ := e.do(t, "GET", "/api/apps", nil); st != 401 {
		t.Errorf("after logout: %d", st)
	}
}
