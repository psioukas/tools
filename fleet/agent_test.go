package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testToken = "s3cret-token"

type agentEnv struct {
	dir string
	env string // allowed file
	ts  *httptest.Server
	fp  string
	srv *agentServer
}

func newAgentEnv(t *testing.T, mutate func(*agentConfig, string)) *agentEnv {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e := &agentEnv{dir: dir, env: filepath.Join(dir, "app.env")}
	sum := sha256.Sum256([]byte(testToken))
	cfg := &agentConfig{
		TokenSHA256: hex.EncodeToString(sum[:]),
		Allow:       []string{e.env, filepath.Join(dir, "link.env")},
		Reload:      map[string]string{"ok": "echo hello; echo oops >&2", "fail": "echo bad; exit 3"},
	}
	if mutate != nil {
		mutate(cfg, dir)
	}
	e.srv, err = newAgentServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.srv.logger.SetOutput(io.Discard)
	certPEM, keyPEM, fp, err := genSelfSigned([]string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	e.fp = fp
	e.ts = httptest.NewUnstartedServer(e.srv.handler())
	e.ts.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	e.ts.StartTLS()
	t.Cleanup(e.ts.Close)
	return e
}

func (e *agentEnv) target(t *testing.T) *Target {
	t.Helper()
	t.Setenv("TEST_AGENT_TOKEN", testToken)
	return &Target{Driver: "agent", File: e.env, Reload: "ok", AgentURL: e.ts.URL, AgentFingerprint: e.fp, AgentTokenEnv: "TEST_AGENT_TOKEN"}
}

// raw does an authenticated (or not) request using the pinned client.
func (e *agentEnv) raw(t *testing.T, method, path string, q url.Values, token string, body []byte) (int, string) {
	t.Helper()
	d, err := newAgentDriver(&Target{File: e.env, AgentURL: e.ts.URL, AgentFingerprint: e.fp, AgentTokenEnv: "X"})
	if err != nil {
		t.Fatal(err)
	}
	u := e.ts.URL + path
	if q != nil {
		u += "?" + q.Encode()
	}
	req, _ := http.NewRequest(method, u, bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := d.(*agentDriver).client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func fq(p string) url.Values { return url.Values{"path": {p}} }

func TestAgentReadWriteBackupMode(t *testing.T) {
	e := newAgentEnv(t, nil)
	if c, _ := e.raw(t, "GET", "/v1/file", fq(e.env), testToken, nil); c != 404 {
		t.Fatalf("missing file: %d", c)
	}
	if c, _ := e.raw(t, "PUT", "/v1/file", fq(e.env), testToken, []byte("A=1\n")); c != 204 {
		t.Fatalf("put: %d", c)
	}
	st, _ := os.Stat(e.env)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("new file mode %v", st.Mode().Perm())
	}
	if _, err := os.Stat(e.env + ".bak"); !os.IsNotExist(err) {
		t.Fatal("no backup expected for new file")
	}
	os.Chmod(e.env, 0o640)
	if c, _ := e.raw(t, "PUT", "/v1/file", fq(e.env), testToken, []byte("A=2\n")); c != 204 {
		t.Fatal("second put")
	}
	if b, _ := os.ReadFile(e.env); string(b) != "A=2\n" {
		t.Fatalf("content %q", b)
	}
	if b, _ := os.ReadFile(e.env + ".bak"); string(b) != "A=1\n" {
		t.Fatalf("backup %q", b)
	}
	for _, p := range []string{e.env, e.env + ".bak"} {
		if st, _ := os.Stat(p); st.Mode().Perm() != 0o640 {
			t.Fatalf("%s mode %v", p, st.Mode().Perm())
		}
	}
	if c, b := e.raw(t, "GET", "/v1/file", fq(e.env), testToken, nil); c != 200 || b != "A=2\n" {
		t.Fatalf("get %d %q", c, b)
	}
	if c, _ := e.raw(t, "GET", "/v1/health", nil, testToken, nil); c != 200 {
		t.Fatal("health")
	}
	ents, _ := os.ReadDir(e.dir)
	for _, en := range ents {
		if strings.HasPrefix(en.Name(), ".fleet-agent-") {
			t.Fatalf("temp file left: %s", en.Name())
		}
	}
}

func TestAgentAllowlistAndTraversal(t *testing.T) {
	e := newAgentEnv(t, nil)
	other := filepath.Join(e.dir, "other.env")
	os.WriteFile(other, []byte("X=1"), 0o600)
	for _, p := range []string{other, "relative.env", "", filepath.Join(e.dir, "*.env"), "/etc/passwd"} {
		if c, _ := e.raw(t, "GET", "/v1/file", fq(p), testToken, nil); c != 400 && c != 403 {
			t.Fatalf("path %q: %d", p, c)
		}
		if c, _ := e.raw(t, "PUT", "/v1/file", fq(p), testToken, []byte("x")); c != 400 && c != 403 {
			t.Fatalf("put path %q: %d", p, c)
		}
	}
	// traversal that lands on a non-allowed file
	if c, _ := e.raw(t, "GET", "/v1/file", fq(e.dir+"/sub/../other.env"), testToken, nil); c != 403 {
		t.Fatalf("traversal: %d", c)
	}
	if b, _ := os.ReadFile(other); string(b) != "X=1" {
		t.Fatal("other file changed")
	}
}

func TestAgentSymlinkRefused(t *testing.T) {
	e := newAgentEnv(t, nil)
	secret := filepath.Join(e.dir, "secret")
	os.WriteFile(secret, []byte("TOP"), 0o600)
	link := filepath.Join(e.dir, "link.env") // allowed name, but a symlink
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}
	if c, _ := e.raw(t, "GET", "/v1/file", fq(link), testToken, nil); c != 403 {
		t.Fatalf("symlink get: %d", c)
	}
	if c, _ := e.raw(t, "PUT", "/v1/file", fq(link), testToken, []byte("pwn")); c != 403 {
		t.Fatalf("symlink put: %d", c)
	}
	if b, _ := os.ReadFile(secret); string(b) != "TOP" {
		t.Fatal("symlink target modified")
	}
}

func TestAgentParentSwapRefused(t *testing.T) {
	var sub string
	e := newAgentEnv(t, func(c *agentConfig, dir string) {
		sub = filepath.Join(dir, "sub")
		os.Mkdir(sub, 0o755)
		c.Allow = append(c.Allow, filepath.Join(sub, "x.env"))
	})
	os.Rename(sub, sub+".old")
	os.Mkdir(filepath.Join(e.dir, "evil"), 0o755)
	os.Symlink(filepath.Join(e.dir, "evil"), sub)
	if c, _ := e.raw(t, "PUT", "/v1/file", fq(filepath.Join(sub, "x.env")), testToken, []byte("x")); c != 403 {
		t.Fatalf("parent swap: %d", c)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "evil", "x.env")); err == nil {
		t.Fatal("written through swapped parent")
	}
}

func TestAgentSizeLimit(t *testing.T) {
	e := newAgentEnv(t, nil)
	if c, _ := e.raw(t, "PUT", "/v1/file", fq(e.env), testToken, bytes.Repeat([]byte("a"), 1<<20)); c != 204 {
		t.Fatalf("exactly 1 MiB: %d", c)
	}
	if c, _ := e.raw(t, "PUT", "/v1/file", fq(e.env), testToken, bytes.Repeat([]byte("a"), 1<<20+1)); c != 413 {
		t.Fatalf("over limit: %d", c)
	}
	if b, _ := os.ReadFile(e.env); len(b) != 1<<20 {
		t.Fatal("file replaced by oversized body")
	}
}

func TestAgentAuthAndRateLimit(t *testing.T) {
	e := newAgentEnv(t, nil)
	if c, b := e.raw(t, "GET", "/v1/health", nil, "", nil); c != 401 || strings.TrimSpace(b) != "" {
		t.Fatalf("missing token: %d %q", c, b)
	}
	for i := 0; i < 4; i++ {
		if c, _ := e.raw(t, "GET", "/v1/health", nil, "wrong", nil); c != 401 {
			t.Fatalf("wrong token: %d", c)
		}
	}
	// fifth failure triggers the lockout; even the right token is then refused
	e.raw(t, "GET", "/v1/health", nil, "wrong", nil)
	if c, _ := e.raw(t, "GET", "/v1/health", nil, testToken, nil); c != 429 {
		t.Fatalf("expected lockout, got %d", c)
	}
}

func TestRateLimiterBackoff(t *testing.T) {
	now := time.Unix(1000, 0)
	rl := newRateLimiter(func() time.Time { return now })
	lock := func() {
		for i := 0; i < 5; i++ {
			rl.fail("1.2.3.4")
		}
	}
	lock()
	if !rl.locked("1.2.3.4") || rl.locked("9.9.9.9") {
		t.Fatal("lock state")
	}
	now = now.Add(10*time.Minute + time.Second)
	if rl.locked("1.2.3.4") {
		t.Fatal("should unlock after 10 minutes")
	}
	lock()
	now = now.Add(10*time.Minute + time.Second)
	if !rl.locked("1.2.3.4") {
		t.Fatal("second lockout should be 20 minutes")
	}
	now = now.Add(10 * time.Minute)
	if rl.locked("1.2.3.4") {
		t.Fatal("should unlock after 20 minutes")
	}
}

func TestAgentReloadByName(t *testing.T) {
	e := newAgentEnv(t, nil)
	c, b := e.raw(t, "POST", "/v1/reload", nil, testToken, []byte(`{"name":"ok"}`))
	if c != 200 || !strings.Contains(b, `"exit_code":0`) || !strings.Contains(b, "hello") || !strings.Contains(b, "oops") {
		t.Fatalf("reload ok: %d %s", c, b)
	}
	c, b = e.raw(t, "POST", "/v1/reload", nil, testToken, []byte(`{"name":"fail"}`))
	if c != 200 || !strings.Contains(b, `"exit_code":3`) {
		t.Fatalf("reload fail: %d %s", c, b)
	}
	if c, _ := e.raw(t, "POST", "/v1/reload", nil, testToken, []byte(`{"name":"echo pwned"}`)); c != 404 {
		t.Fatalf("unknown name: %d", c)
	}
	// output is capped at the last 4 KiB
	e2 := newAgentEnv(t, func(c *agentConfig, _ string) {
		c.Reload = map[string]string{"big": "head -c 20000 /dev/zero | tr '\\0' x"}
	})
	_, b = e2.raw(t, "POST", "/v1/reload", nil, testToken, []byte(`{"name":"big"}`))
	if n := strings.Count(strings.TrimPrefix(b, `{"exit_code":0,"output":"`), "x"); n != 4096 {
		t.Fatalf("output tail %d", n)
	}
}

func TestAgentDriverRoundTrip(t *testing.T) {
	e := newAgentEnv(t, nil)
	d, err := newDriver(e.target(t))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(d.Describe(), "agent:https://") || !strings.HasSuffix(d.Describe(), " "+e.env) {
		t.Fatal(d.Describe())
	}
	ctx := context.Background()
	if _, ok, err := d.Read(ctx); err != nil || ok {
		t.Fatalf("read missing: %v %v", ok, err)
	}
	if err := d.Write(ctx, []byte("K=v\n")); err != nil {
		t.Fatal(err)
	}
	b, ok, err := d.Read(ctx)
	if err != nil || !ok || string(b) != "K=v\n" {
		t.Fatalf("read: %q %v %v", b, ok, err)
	}
	if err := d.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	tg := e.target(t)
	tg.Reload = "fail"
	d, _ = newDriver(tg)
	if err := d.Reload(ctx); err == nil || !strings.Contains(err.Error(), "3") {
		t.Fatalf("expected exit 3 error, got %v", err)
	}
	tg.Reload = "nope"
	d, _ = newDriver(tg)
	if err := d.Reload(ctx); err == nil {
		t.Fatal("unknown reload name must error")
	}
	tg.Reload = ""
	d, _ = newDriver(tg)
	if err := d.Reload(ctx); !errors.Is(err, errNoReload) {
		t.Fatalf("want errNoReload, got %v", err)
	}
	// wrong token
	t.Setenv("TEST_AGENT_TOKEN", "bad")
	d, _ = newDriver(e.target(t))
	t.Setenv("TEST_AGENT_TOKEN", "bad")
	if _, _, err := d.Read(ctx); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("want 401 error, got %v", err)
	}
}

func TestAgentFingerprintPinning(t *testing.T) {
	e := newAgentEnv(t, nil)
	tg := e.target(t)
	// colons and upper case are accepted
	var colon []string
	for i := 0; i < len(e.fp); i += 2 {
		colon = append(colon, strings.ToUpper(e.fp[i:i+2]))
	}
	tg.AgentFingerprint = strings.Join(colon, ":")
	d, err := newDriver(tg)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.Read(context.Background()); err != nil {
		t.Fatalf("pinned read: %v", err)
	}
	// mismatch must fail closed, before any request (and the token) is sent
	tg.AgentFingerprint = strings.Repeat("ab", 32)
	d, _ = newDriver(tg)
	_, _, err = d.Read(context.Background())
	if err == nil || !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("want fingerprint mismatch, got %v", err)
	}
	if err := d.Write(context.Background(), []byte("x")); err == nil {
		t.Fatal("write must refuse on mismatch")
	}
	if _, err := os.Stat(e.env); err == nil {
		t.Fatal("file must not exist")
	}
}

func TestAgentTLS13Only(t *testing.T) {
	e := newAgentEnv(t, nil)
	conn, err := tls.Dial("tcp", e.ts.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12})
	if err == nil {
		conn.Close()
		t.Fatal("TLS 1.2 must be refused")
	}
}

func TestAgentTokenFilePermissions(t *testing.T) {
	e := newAgentEnv(t, nil)
	tf := filepath.Join(t.TempDir(), "token")
	os.WriteFile(tf, []byte(testToken+"\n"), 0o644)
	os.Chmod(tf, 0o644)
	tg := &Target{Driver: "agent", File: e.env, AgentURL: e.ts.URL, AgentFingerprint: e.fp, AgentTokenFile: tf}
	d, err := newDriver(tg)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.Read(context.Background()); err == nil || !strings.Contains(err.Error(), "too open") {
		t.Fatalf("want permission refusal, got %v", err)
	}
	os.Chmod(tf, 0o600)
	if _, _, err := d.Read(context.Background()); err != nil {
		t.Fatalf("0600 token file: %v", err)
	}
	os.Chmod(tf, 0o400)
	if _, _, err := d.Read(context.Background()); err != nil {
		t.Fatalf("0400 token file: %v", err)
	}
}

func TestAgentTargetValidation(t *testing.T) {
	fp := strings.Repeat("0a", 32)
	ok := Target{Driver: "agent", File: "/srv/.env", AgentURL: "https://10.0.0.5:8787", AgentFingerprint: fp, AgentTokenEnv: "T"}
	if err := ok.validate(); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(*Target){
		"http url":      func(x *Target) { x.AgentURL = "http://10.0.0.5:8787" },
		"no url":        func(x *Target) { x.AgentURL = "" },
		"no fp":         func(x *Target) { x.AgentFingerprint = "" },
		"bad fp":        func(x *Target) { x.AgentFingerprint = "xyz" },
		"no token":      func(x *Target) { x.AgentTokenEnv = "" },
		"both tokens":   func(x *Target) { x.AgentTokenFile = "/x" },
		"no file":       func(x *Target) { x.File = "" },
		"unknown extra": func(x *Target) { x.Driver = "agnt" },
	}
	for name, f := range bad {
		x := ok
		f(&x)
		if err := x.validate(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestAgentConfigRules(t *testing.T) {
	if err := checkListen("0.0.0.0:8787", false); err == nil {
		t.Fatal("0.0.0.0 must be refused")
	}
	if err := checkListen("[::]:8787", false); err == nil {
		t.Fatal(":: must be refused")
	}
	if err := checkListen(":8787", false); err == nil {
		t.Fatal("empty host must be refused")
	}
	if err := checkListen("0.0.0.0:8787", true); err != nil {
		t.Fatal(err)
	}
	if err := checkListen("127.0.0.1:8787", false); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("x"))
	h := hex.EncodeToString(sum[:])
	if _, err := newAgentServer(&agentConfig{TokenSHA256: h, Allow: []string{"/tmp/*.env"}}); err == nil {
		t.Fatal("glob must be refused")
	}
	if _, err := newAgentServer(&agentConfig{TokenSHA256: h, Allow: []string{"rel.env"}}); err == nil {
		t.Fatal("relative must be refused")
	}
	if _, err := newAgentServer(&agentConfig{TokenSHA256: "abc"}); err == nil {
		t.Fatal("bad hash must be refused")
	}
}

func TestAgentInit(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "agent")
	if code := cmdAgentInit([]string{"-dir", dir, "-host", "agent.internal,10.0.0.9"}); code != 0 {
		t.Fatal("init failed")
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", st.Mode().Perm())
	}
	if st, _ := os.Stat(filepath.Join(dir, "key.pem")); st.Mode().Perm() != 0o600 {
		t.Fatal("key mode")
	}
	cfg, err := loadAgentConfig(filepath.Join(dir, "agent.yaml"))
	if err != nil || len(cfg.TokenSHA256) != 64 {
		t.Fatalf("config: %v %+v", err, cfg)
	}
	if code := cmdAgentInit([]string{"-dir", dir}); code == 0 {
		t.Fatal("must refuse to overwrite without -force")
	}
	if code := cmdAgentInit([]string{"-dir", dir, "-force"}); code != 0 {
		t.Fatal("-force should overwrite")
	}
}
