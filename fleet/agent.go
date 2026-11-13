package main

// The fleet agent: a small HTTPS daemon that lets the manager read and write a fixed
// list of env files and run a fixed list of named reload commands on a host that is not
// reachable over ssh. The agent's own config (agent.yaml) is the only authority on what
// may be touched; the manager can only name things that config already allows.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	agentDefaultListen = "127.0.0.1:8787"
	agentDefaultMax    = 1 << 20
	agentReloadTimeout = 60 * time.Second
	agentOutputTail    = 4096
)

// agentConfig is agent.yaml.
type agentConfig struct {
	Listen      string            `yaml:"listen"`
	TokenSHA256 string            `yaml:"token_sha256"`
	Allow       []string          `yaml:"allow"`
	Reload      map[string]string `yaml:"reload"`
	MaxBytes    int64             `yaml:"max_bytes"`
	Cert        string            `yaml:"cert"` // default cert.pem next to agent.yaml
	Key         string            `yaml:"key"`  // default key.pem next to agent.yaml
}

func loadAgentConfig(path string) (*agentConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c agentConfig
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	dir := filepath.Dir(path)
	if c.Cert == "" {
		c.Cert = filepath.Join(dir, "cert.pem")
	}
	if c.Key == "" {
		c.Key = filepath.Join(dir, "key.pem")
	}
	return &c, nil
}

// ---- server ---------------------------------------------------------------------------------

type agentServer struct {
	hash     []byte
	allow    map[string]string // cleaned allowed path -> resolved parent dir at startup
	reload   map[string]string
	maxBytes int64
	rl       *rateLimiter
	logger   *log.Logger
}

func newAgentServer(c *agentConfig) (*agentServer, error) {
	hash, err := hex.DecodeString(strings.TrimSpace(c.TokenSHA256))
	if err != nil || len(hash) != sha256.Size {
		return nil, errors.New("token_sha256 must be a 64 character hex SHA-256")
	}
	s := &agentServer{
		hash:     hash,
		allow:    map[string]string{},
		reload:   map[string]string{},
		maxBytes: c.MaxBytes,
		rl:       newRateLimiter(time.Now),
		logger:   log.New(os.Stderr, "fleet-agent: ", log.LstdFlags),
	}
	if s.maxBytes <= 0 {
		s.maxBytes = agentDefaultMax
	}
	for _, p := range c.Allow {
		if !filepath.IsAbs(p) || strings.ContainsAny(p, "*?[\x00") {
			return nil, fmt.Errorf("allow entry %q must be an exact absolute path (no globs)", p)
		}
		p = filepath.Clean(p)
		parent, err := filepath.EvalSymlinks(filepath.Dir(p))
		if err != nil {
			return nil, fmt.Errorf("allow entry %q: %w", p, err)
		}
		s.allow[p] = parent
	}
	for n, cmd := range c.Reload {
		if n == "" || strings.TrimSpace(cmd) == "" {
			return nil, errors.New("reload entries need a name and a command")
		}
		s.reload[n] = cmd
	}
	return s, nil
}

func (s *agentServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", s.health)
	mux.HandleFunc("/v1/file", s.file)
	mux.HandleFunc("/v1/reload", s.doReload)
	return s.logging(s.auth(mux))
}

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (r *statusRecorder) WriteHeader(c int) { r.code = c; r.ResponseWriter.WriteHeader(c) }

func remoteIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// logging records method, path (never the query, body or headers), status and peer IP.
func (s *agentServer) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, code: 200}
		next.ServeHTTP(rec, r)
		s.logger.Printf("%s %s %d %s", r.Method, r.URL.Path, rec.code, remoteIP(r))
	})
}

func (s *agentServer) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := remoteIP(r)
		if s.rl.locked(ip) {
			http.Error(w, "", http.StatusTooManyRequests)
			return
		}
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		good := false
		if ok {
			sum := sha256.Sum256([]byte(tok))
			good = subtle.ConstantTimeCompare(sum[:], s.hash) == 1
		}
		if !good {
			s.rl.fail(ip)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}
		s.rl.ok(ip)
		next.ServeHTTP(w, r)
	})
}

func (s *agentServer) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// resolve applies the path rules and returns the real file path to operate on.
func (s *agentServer) resolve(p string) (string, int, string) {
	if p == "" || strings.ContainsRune(p, 0) || !filepath.IsAbs(p) {
		return "", http.StatusBadRequest, "path must be absolute"
	}
	p = filepath.Clean(p)
	parent, ok := s.allow[p]
	if !ok {
		return "", http.StatusForbidden, "path not allowed"
	}
	cur, err := filepath.EvalSymlinks(filepath.Dir(p))
	if err != nil || cur != parent {
		return "", http.StatusForbidden, "path not allowed"
	}
	if st, err := os.Lstat(p); err == nil {
		if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
			return "", http.StatusForbidden, "path not allowed"
		}
	} else if !os.IsNotExist(err) {
		return "", http.StatusInternalServerError, "cannot stat file"
	}
	return filepath.Join(parent, filepath.Base(p)), 0, ""
}

func (s *agentServer) file(w http.ResponseWriter, r *http.Request) {
	real, code, msg := s.resolve(r.URL.Query().Get("path"))
	if code != 0 {
		http.Error(w, msg, code)
		return
	}
	switch r.Method {
	case http.MethodGet:
		b, err := os.ReadFile(real)
		if os.IsNotExist(err) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, "read failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(b)
	case http.MethodPut:
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.maxBytes))
		if err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				http.Error(w, "too large", http.StatusRequestEntityTooLarge)
			} else {
				http.Error(w, "bad body", http.StatusBadRequest)
			}
			return
		}
		if err := writeAtomic(real, body); err != nil {
			s.logger.Printf("write failed: %v", err)
			http.Error(w, "write failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// writeAtomic replaces path via a temp file in the same directory, keeping the previous
// content as path.bak with the same mode. New files are 0600; existing files keep their mode.
func writeAtomic(path string, content []byte) error {
	mode := os.FileMode(0o600)
	old, oldErr := os.ReadFile(path)
	if oldErr == nil {
		st, err := os.Stat(path)
		if err != nil {
			return err
		}
		mode = st.Mode().Perm()
		bak := path + ".bak"
		if err := os.Remove(bak); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("backup: %w", err)
		}
		f, err := os.OpenFile(bak, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return fmt.Errorf("backup: %w", err)
		}
		if _, err := f.Write(old); err != nil {
			f.Close()
			return fmt.Errorf("backup: %w", err)
		}
		if err := f.Chmod(mode); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	} else if !os.IsNotExist(oldErr) {
		return oldErr
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".fleet-agent-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

type tailBuffer struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.max {
		t.buf = append([]byte(nil), t.buf[len(t.buf)-t.max:]...)
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}

type reloadResult struct {
	ExitCode int    `json:"exit_code"`
	Output   string `json:"output"`
}

func (s *agentServer) doReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	command, ok := s.reload[req.Name]
	if !ok {
		http.Error(w, "unknown reload name", http.StatusNotFound)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), agentReloadTimeout)
	defer cancel()
	out := &tailBuffer{max: agentOutputTail}
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	cmd.Stdout, cmd.Stderr = out, out
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	res := reloadResult{}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ctx.Err() == nil {
			res.ExitCode = ee.ExitCode()
		} else {
			res.ExitCode = -1
			if ctx.Err() != nil {
				out.Write([]byte("\n[timed out]"))
			} else {
				out.Write([]byte("\n[" + err.Error() + "]"))
			}
		}
	}
	res.Output = out.String()
	writeJSON(w, 200, res)
}

// ---- rate limiting ------------------------------------------------------------------------------

type rlEntry struct {
	fails int
	until time.Time
	dur   time.Duration
}

// rateLimiter locks out an IP for 10 minutes after 5 failed auths, doubling each time.
type rateLimiter struct {
	mu  sync.Mutex
	now func() time.Time
	m   map[string]*rlEntry
}

func newRateLimiter(now func() time.Time) *rateLimiter {
	return &rateLimiter{now: now, m: map[string]*rlEntry{}}
}

func (r *rateLimiter) locked(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.m[ip]
	return e != nil && r.now().Before(e.until)
}

func (r *rateLimiter) fail(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.m[ip]
	if e == nil {
		e = &rlEntry{}
		r.m[ip] = e
	}
	e.fails++
	if e.fails >= 5 {
		e.fails = 0
		if e.dur == 0 {
			e.dur = 10 * time.Minute
		} else {
			e.dur *= 2
		}
		e.until = r.now().Add(e.dur)
	}
}

func (r *rateLimiter) ok(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.m[ip]; e != nil {
		e.fails = 0
	}
}

// ---- certificate and init -------------------------------------------------------------------

func certFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// genSelfSigned makes an ECDSA P-256 server certificate valid for hosts (names or IPs) for 5 years.
func genSelfSigned(hosts []string) (certPEM, keyPEM []byte, fp string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, nil, "", err
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "fleet-agent"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, "", err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, "", err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	return certPEM, keyPEM, certFingerprint(der), nil
}

func defaultAgentDir() string {
	if os.Geteuid() == 0 {
		return "/etc/fleet-agent"
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".config", "fleet-agent")
	}
	return "fleet-agent"
}

const sampleAgentYAML = `# fleet agent config: the ONLY place that decides what this agent may touch.
listen: %s            # 0.0.0.0 / :: are refused unless you run with -allow-public
token_sha256: %s
max_bytes: 1048576
# Exact absolute paths of env files the manager may read and write (no globs).
allow:
  - /srv/app/.env
# Named reload commands; the manager sends only a name, never a command.
reload:
  app: docker compose --project-directory /srv/app up -d --force-recreate
`

func cmdAgentInit(args []string) int {
	fs := flag.NewFlagSet("agent init", flag.ContinueOnError)
	dir := fs.String("dir", "", "config directory (default /etc/fleet-agent as root, else ~/.config/fleet-agent)")
	hosts := fs.String("host", "localhost,127.0.0.1", "comma separated DNS names and IPs for the certificate")
	force := fs.Bool("force", false, "overwrite existing files")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *dir == "" {
		*dir = defaultAgentDir()
	}
	var hl []string
	for _, h := range strings.Split(*hosts, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hl = append(hl, h)
		}
	}
	if len(hl) == 0 {
		fmt.Fprintln(os.Stderr, "error: -host needs at least one name or IP")
		return 2
	}
	files := []string{"agent.yaml", "cert.pem", "key.pem"}
	if !*force {
		for _, f := range files {
			if _, err := os.Lstat(filepath.Join(*dir, f)); err == nil {
				fmt.Fprintf(os.Stderr, "error: %s already exists (use -force to overwrite)\n", filepath.Join(*dir, f))
				return 1
			}
		}
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if err := os.Chmod(*dir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	token := hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	certPEM, keyPEM, fp, err := genSelfSigned(hl)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	yml := fmt.Sprintf(sampleAgentYAML, agentDefaultListen, hex.EncodeToString(sum[:]))
	for _, w := range []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"key.pem", keyPEM, 0o600},
		{"cert.pem", certPEM, 0o644},
		{"agent.yaml", []byte(yml), 0o600},
	} {
		p := filepath.Join(*dir, w.name)
		os.Remove(p) // never write through a pre-existing link
		if err := os.WriteFile(p, w.data, w.mode); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
	}
	fmt.Fprintf(os.Stderr, "wrote %s (agent.yaml, cert.pem, key.pem)\n", *dir)
	fmt.Fprintf(os.Stderr, "certificate sha256 (pin as agent_fingerprint on the manager):\n%s\n", fp)
	fmt.Fprintln(os.Stderr, "token (shown once; only its hash is stored). Give it to the manager via an env var or a 0600 file:")
	fmt.Println(token)
	fmt.Fprintf(os.Stderr, "now edit %s: set `allow` and `reload`, then run `fleet agent run -config %s`\n",
		filepath.Join(*dir, "agent.yaml"), filepath.Join(*dir, "agent.yaml"))
	return 0
}

// checkListen refuses wildcard addresses unless explicitly allowed.
func checkListen(addr string, allowPublic bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("listen %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if (host == "" || (ip != nil && ip.IsUnspecified())) && !allowPublic {
		return fmt.Errorf("listen %q is a wildcard address; bind to a private interface IP or pass -allow-public", addr)
	}
	return nil
}

func cmdAgentRun(args []string) int {
	fs := flag.NewFlagSet("agent run", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "agent.yaml (default DIR/agent.yaml)")
	allowPublic := fs.Bool("allow-public", false, "permit listening on 0.0.0.0 or ::")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *cfgPath == "" {
		*cfgPath = filepath.Join(defaultAgentDir(), "agent.yaml")
	}
	cfg, err := loadAgentConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if cfg.Listen == "" {
		cfg.Listen = agentDefaultListen
	}
	if err := checkListen(cfg.Listen, *allowPublic); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if st, err := os.Stat(cfg.Key); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	} else if st.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(os.Stderr, "error: %s must not be accessible by group or others (chmod 600)\n", cfg.Key)
		return 1
	}
	cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	as, err := newAgentServer(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           as.handler(),
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          as.logger,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServeTLS("", "") }()
	as.logger.Printf("listening on %s (%d files, %d reload commands)", cfg.Listen, len(as.allow), len(as.reload))
	select {
	case err := <-errc:
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	as.logger.Printf("stopped")
	return 0
}

const agentUsage = `usage:
  fleet agent init [-dir DIR] [-host NAME,IP...] [-force]
  fleet agent run [-config FILE] [-allow-public]
`

func cmdAgent(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, agentUsage)
		return 2
	}
	switch args[0] {
	case "init":
		return cmdAgentInit(args[1:])
	case "run":
		return cmdAgentRun(args[1:])
	}
	fmt.Fprint(os.Stderr, agentUsage)
	return 2
}
