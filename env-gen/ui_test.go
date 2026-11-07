package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTOTPVector(t *testing.T) { // RFC 6238 appendix B, SHA-1, T=59s -> counter 1
	if got := totpAt([]byte("12345678901234567890"), 1); got != "287082" {
		t.Fatalf("got %s", got)
	}
	var last int64
	secret := []byte("12345678901234567890")
	now := time.Unix(59, 0)
	if !verifyTOTP(secret, "287082", now, &last) {
		t.Fatal("valid code rejected")
	}
	if verifyTOTP(secret, "287082", now, &last) {
		t.Fatal("replayed code accepted")
	}
}

func TestLimiter(t *testing.T) {
	l := newLimiter()
	now := time.Now()
	for i := 0; i < 5; i++ {
		if ok, _ := l.allow("1.1.1.1", now); !ok {
			t.Fatalf("locked too early at %d", i)
		}
		l.fail("1.1.1.1", now)
	}
	if ok, wait := l.allow("1.1.1.1", now); ok || wait < 9*time.Minute {
		t.Fatalf("expected lockout, got ok=%v wait=%v", ok, wait)
	}
	if ok, _ := l.allow("2.2.2.2", now); !ok {
		t.Fatal("other IP should still be allowed")
	}
	l.ok("1.1.1.1")
	if ok, _ := l.allow("1.1.1.1", now); !ok {
		t.Fatal("success should reset")
	}
}

func TestSafePath(t *testing.T) {
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	os.MkdirAll(filepath.Join(root, "app"), 0o755)
	outside := t.TempDir()
	os.Symlink(outside, filepath.Join(root, "link"))
	s := &uiServer{root: root}
	good := []string{".env", "app/.env", "app/.env.example", "app/prod.env"}
	bad := []string{"", "/etc/passwd", "../x/.env", "app/../../x/.env", "app/notes.txt", "app/.env.bak", "link/.env", "nodir/.env", "app/id_rsa"}
	for _, p := range good {
		if _, err := s.safePath(p); err != nil {
			t.Errorf("%q rejected: %v", p, err)
		}
	}
	for _, p := range bad {
		if _, err := s.safePath(p); err == nil {
			t.Errorf("%q should be rejected", p)
		}
	}
}

// fake bw: unlock accepts "pw", get/create/edit keep JSON files in $FAKE_VAULT.
const fakeBW = `#!/usr/bin/env bash
v="$FAKE_VAULT"; mkdir -p "$v"
case "$1 $2" in
 "status ") echo '{"serverUrl":"https://v.example","userEmail":"me@x","status":"locked"}' ;;
 "unlock --raw") [[ "$ENVGEN_BW_PW" == "pw" ]] && printf 'SESS' || { echo "Invalid master password." >&2; exit 1; } ;;
 "get item") [[ -f "$v/$3" ]] && cat "$v/$3" || { echo "Not found." >&2; exit 1; } ;;
 "create item") base64 -d | python3 -c 'import sys,json;d=json.load(sys.stdin);d["id"]=d["name"];open(sys.argv[1]+"/"+d["name"],"w").write(json.dumps(d));print(json.dumps(d))' "$v" ;;
 "edit item") base64 -d | python3 -c 'import sys,json;d=json.load(sys.stdin);open(sys.argv[1]+"/"+sys.argv[2],"w").write(json.dumps(d));print(json.dumps(d))' "$v" "$3" ;;
esac
`

type uiEnv struct {
	s      *uiServer
	srv    *httptest.Server
	client *http.Client
	root   string
	vault  string
	secret []byte
	csrf   string
}

func newUIEnv(t *testing.T) *uiEnv {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bw")
	os.WriteFile(bin, []byte(fakeBW), 0o755)
	root, _ := filepath.EvalSymlinks(filepath.Join(dir, "projects"))
	root = filepath.Join(dir, "projects")
	os.MkdirAll(filepath.Join(root, "shop"), 0o755)
	os.WriteFile(filepath.Join(root, "shop", ".env.example"), []byte("APP=Shop\nDB_PASSWORD=changeme\n"), 0o644)
	os.WriteFile(filepath.Join(root, "shop", ".env"), []byte("PORT=3000\nTOKEN=abc\n"), 0o600)
	root, _ = filepath.EvalSymlinks(root)
	vault := filepath.Join(dir, "vault")
	t.Setenv("FAKE_VAULT", vault)
	t.Setenv("ENV_GEN_CACHE", filepath.Join(dir, "cache.json"))
	secret := []byte("12345678901234567890")
	s := &uiServer{root: root, insecure: true, idle: time.Minute, maxAge: time.Hour, totp: secret, bin: bin,
		hosts: map[string]bool{}, lim: newLimiter()}
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return &uiEnv{s: s, srv: srv, client: &http.Client{Jar: jar}, root: root, vault: vault, secret: secret}
}

func (e *uiEnv) do(t *testing.T, method, path string, body any, csrf bool) (int, map[string]any) {
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
	if csrf {
		req.Header.Set("X-CSRF-Token", e.csrf)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (e *uiEnv) login(t *testing.T) {
	t.Helper()
	// each login needs a fresh TOTP step (replay protection): move the replay marker back
	e.s.mu.Lock()
	e.s.lastTOTP = 0
	e.s.mu.Unlock()
	code := totpAt(e.secret, time.Now().Unix()/30)
	st, out := e.do(t, "POST", "/api/login", map[string]string{"password": "pw", "code": code}, false)
	if st != 200 {
		t.Fatalf("login: %d %v", st, out)
	}
	e.csrf = out["csrf"].(string)
}

func TestUIRequiresAuth(t *testing.T) {
	e := newUIEnv(t)
	for _, p := range []string{"/api/projects", "/api/file?path=shop/.env", "/api/value?path=shop/.env&key=TOKEN", "/api/vault/recent"} {
		if st, _ := e.do(t, "GET", p, nil, false); st != 401 {
			t.Errorf("%s: want 401, got %d", p, st)
		}
	}
	if st, _ := e.do(t, "POST", "/api/save", map[string]any{}, false); st != 401 {
		t.Errorf("save without login: %d", st)
	}
}

func TestUILoginFailures(t *testing.T) {
	e := newUIEnv(t)
	code := totpAt(e.secret, time.Now().Unix()/30)
	if st, _ := e.do(t, "POST", "/api/login", map[string]string{"password": "pw", "code": "000000"}, false); st != 401 {
		t.Errorf("bad code: %d", st)
	}
	if st, _ := e.do(t, "POST", "/api/login", map[string]string{"password": "wrong", "code": code}, false); st != 401 {
		t.Errorf("bad password: %d", st)
	}
}

func TestUIFlow(t *testing.T) {
	e := newUIEnv(t)
	e.login(t)

	// CSRF: state-changing request without the token is refused
	if st, _ := e.do(t, "POST", "/api/save", map[string]any{"path": "shop/.env"}, false); st != 403 {
		t.Errorf("missing csrf: %d", st)
	}

	_, out := e.do(t, "GET", "/api/projects", nil, false)
	if !strings.Contains(fmt.Sprint(out), "shop") {
		t.Fatalf("projects: %v", out)
	}

	// secrets are not sent in file listings, only on explicit reveal
	_, f := e.do(t, "GET", "/api/file?path=shop/.env", nil, false)
	raw, _ := json.Marshal(f)
	if strings.Contains(string(raw), "abc") {
		t.Fatalf("secret value leaked in listing: %s", raw)
	}
	if !strings.Contains(string(raw), "3000") {
		t.Fatalf("non-secret value missing: %s", raw)
	}
	if _, v := e.do(t, "GET", "/api/value?path=shop/.env&key=TOKEN", nil, false); v["value"] != "abc" {
		t.Fatalf("reveal: %v", v)
	}

	// path escape attempts
	for _, p := range []string{"../../etc/passwd", "/etc/passwd", "shop/../../x/.env"} {
		if st, _ := e.do(t, "GET", "/api/file?path="+p, nil, false); st != 400 {
			t.Errorf("%q: %d", p, st)
		}
	}

	// preview changes nothing and stores nothing
	ops := []uiOp{
		{Op: "set", Key: "PORT", Source: &uiSource{Kind: "literal", Value: "4000"}},
		{Op: "set", Key: "SECRET_KEY", Source: &uiSource{Kind: "vwgen", Item: "shop", Field: "SECRET_KEY", Length: 16, Charset: "alnum"}},
		{Op: "delete", Key: "TOKEN"},
	}
	st, pr := e.do(t, "POST", "/api/save", saveReq{Path: "shop/.env", Ops: ops, Preview: true}, true)
	if st != 200 || pr["preview"] != true {
		t.Fatalf("preview: %d %v", st, pr)
	}
	if b, _ := os.ReadFile(filepath.Join(e.root, "shop", ".env")); !strings.Contains(string(b), "3000") {
		t.Fatal("preview wrote the file")
	}
	if _, err := os.Stat(filepath.Join(e.vault, "shop")); err == nil {
		t.Fatal("preview touched the vault")
	}

	// real save with vault backup
	st, sv := e.do(t, "POST", "/api/save", saveReq{Path: "shop/.env", Ops: ops, BackupItem: "shop"}, true)
	if st != 200 || sv["saved"] != true {
		t.Fatalf("save: %d %v", st, sv)
	}
	b, _ := os.ReadFile(filepath.Join(e.root, "shop", ".env"))
	if !strings.Contains(string(b), "PORT=4000") || strings.Contains(string(b), "TOKEN") || !strings.Contains(string(b), "SECRET_KEY=") {
		t.Fatalf("file: %q", b)
	}
	if bak, _ := os.ReadFile(filepath.Join(e.root, "shop", ".env.bak")); !strings.Contains(string(bak), "TOKEN=abc") {
		t.Fatal("no .bak of the previous version")
	}
	vb, _ := os.ReadFile(filepath.Join(e.vault, "shop"))
	if !strings.Contains(string(vb), "PORT") || !strings.Contains(string(vb), "4000") {
		t.Fatalf("vault backup missing: %s", vb)
	}

	// create .env from the example, refusing to overwrite without the flag
	st, _ = e.do(t, "POST", "/api/save", saveReq{Path: "shop/.env.example", To: "shop/.env.new", Ops: []uiOp{
		{Op: "set", Key: "DB_PASSWORD", Source: &uiSource{Kind: "gen", Length: 20, Charset: "hex"}}}}, true)
	if st != 200 {
		t.Fatalf("create from example: %d", st)
	}
	if st, _ := e.do(t, "POST", "/api/save", saveReq{Path: "shop/.env.example", To: "shop/.env.new"}, true); st != 409 {
		t.Errorf("overwrite without flag: %d", st)
	}
	// invalid input
	if st, _ := e.do(t, "POST", "/api/save", saveReq{Path: "shop/.env", Ops: []uiOp{{Op: "set", Key: "bad key", Source: &uiSource{Kind: "literal"}}}}, true); st != 400 {
		t.Errorf("bad key: %d", st)
	}
	if st, _ := e.do(t, "POST", "/api/save", saveReq{Path: "shop/.env", Ops: []uiOp{{Op: "set", Key: "X", Source: &uiSource{Kind: "gen", Length: 2, Charset: "alnum"}}}}, true); st != 400 {
		t.Errorf("short length: %d", st)
	}

	// cross-origin requests are refused
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/logout", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", e.csrf)
	req.Header.Set("Origin", "https://evil.example")
	resp, _ := e.client.Do(req)
	if resp.StatusCode != 403 {
		t.Errorf("cross-origin: %d", resp.StatusCode)
	}

	// logout kills the session
	e.do(t, "POST", "/api/logout", map[string]any{}, true)
	if st, _ := e.do(t, "GET", "/api/projects", nil, false); st != 401 {
		t.Errorf("after logout: %d", st)
	}
}

func TestUIHeadersAndHTTPS(t *testing.T) {
	e := newUIEnv(t)
	resp, _ := http.Get(e.srv.URL + "/")
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "default-src 'none'") || resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Errorf("missing security headers: %v", resp.Header)
	}
	// public mode: plain http through the proxy is refused, and unknown hosts too
	e.s.insecure = false
	e.s.hosts = map[string]bool{"vault.example.com": true}
	req, _ := http.NewRequest("GET", e.srv.URL+"/api/status", nil)
	if r, _ := http.DefaultClient.Do(req); r.StatusCode != 403 {
		t.Errorf("http accepted in public mode: %d", r.StatusCode)
	}
	req.Header.Set("X-Forwarded-Proto", "https")
	if r, _ := http.DefaultClient.Do(req); r.StatusCode != 421 {
		t.Errorf("wrong host accepted: %d", r.StatusCode)
	}
	req.Host = "vault.example.com"
	if r, _ := http.DefaultClient.Do(req); r.StatusCode != 200 {
		t.Errorf("good request refused: %d", r.StatusCode)
	}
}
