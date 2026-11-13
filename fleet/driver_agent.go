package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func init() { registry["agent"] = newAgentDriver }

// normalizeFingerprint accepts hex with optional colons/spaces in any case and
// returns 64 lowercase hex characters.
func normalizeFingerprint(s string) (string, error) {
	s = strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(s)))
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != sha256.Size {
		return "", errors.New("agent_fingerprint must be a SHA-256 in hex (64 hex characters, colons allowed)")
	}
	return s, nil
}

type agentDriver struct {
	base        string
	file        string
	reload      string
	fingerprint string
	tokenEnv    string
	tokenFile   string
	client      *http.Client
}

func newAgentDriver(t *Target) (Driver, error) {
	u, err := url.Parse(t.AgentURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("agent_url must be an https:// URL")
	}
	fp, err := normalizeFingerprint(t.AgentFingerprint)
	if err != nil {
		return nil, err
	}
	d := &agentDriver{
		base: strings.TrimRight(u.String(), "/"), file: t.File, reload: t.Reload,
		fingerprint: fp, tokenEnv: t.AgentTokenEnv, tokenFile: t.AgentTokenFile,
	}
	d.client = &http.Client{
		Timeout: 2 * time.Minute,
		Transport: &http.Transport{
			TLSClientConfig: pinnedTLSConfig(fp),
			Proxy:           nil, // the agent is on a private network; never via a proxy
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return d, nil
}

// pinnedTLSConfig makes the pinned leaf certificate fingerprint the only trust anchor.
func pinnedTLSConfig(fp string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // verification is replaced by the pin below
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("agent presented no certificate")
			}
			got := certFingerprint(raw[0])
			if got != fp {
				return fmt.Errorf("agent certificate fingerprint mismatch: pinned %s, got %s (refusing to connect)", fp, got)
			}
			return nil
		},
	}
}

func (d *agentDriver) token() (string, error) {
	var tok string
	switch {
	case d.tokenEnv != "":
		tok = os.Getenv(d.tokenEnv)
		if tok == "" {
			return "", fmt.Errorf("environment variable %s (agent_token_env) is empty", d.tokenEnv)
		}
	case d.tokenFile != "":
		p := expandHome(d.tokenFile)
		st, err := os.Stat(p)
		if err != nil {
			return "", err
		}
		if !st.Mode().IsRegular() {
			return "", fmt.Errorf("%s is not a regular file", p)
		}
		if st.Mode().Perm()&0o077 != 0 {
			return "", fmt.Errorf("refusing token file %s: mode %04o is too open (chmod 600)", p, st.Mode().Perm())
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return "", err
		}
		tok = strings.TrimSpace(string(b))
		if tok == "" {
			return "", fmt.Errorf("token file %s is empty", p)
		}
	default:
		return "", errors.New("no agent token source configured")
	}
	return tok, nil
}

// validateAgent checks the agent-specific target fields (called from Target.validate).
func (t *Target) validateAgent() error {
	u, err := url.Parse(t.AgentURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("driver agent needs `agent_url` starting with https://")
	}
	if t.AgentFingerprint == "" {
		return fmt.Errorf("driver agent needs `agent_fingerprint`")
	}
	if _, err := normalizeFingerprint(t.AgentFingerprint); err != nil {
		return err
	}
	if (t.AgentTokenEnv == "") == (t.AgentTokenFile == "") {
		return fmt.Errorf("driver agent needs exactly one of `agent_token_env` or `agent_token_file`")
	}
	return nil
}

func (d *agentDriver) Describe() string { return "agent:" + d.base + " " + d.file }

// do sends a request and returns status and (bounded) body.
func (d *agentDriver) do(ctx context.Context, method, path string, q url.Values, ctype string, body []byte) (int, []byte, error) {
	tok, err := d.token()
	if err != nil {
		return 0, nil, err
	}
	u := d.base + path
	if q != nil {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return 0, nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return resp.StatusCode, b, errors.New("agent rejected the token (401)")
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return resp.StatusCode, b, errors.New("agent is rate limiting this client (429): too many failed attempts")
	}
	return resp.StatusCode, b, nil
}

func agentErr(code int, body []byte) error {
	msg := strings.TrimSpace(string(body))
	if len(msg) > 200 {
		msg = msg[:200] + "..."
	}
	return fmt.Errorf("agent returned %d: %s", code, msg)
}

func (d *agentDriver) Read(ctx context.Context) ([]byte, bool, error) {
	code, b, err := d.do(ctx, http.MethodGet, "/v1/file", url.Values{"path": {d.file}}, "", nil)
	if err != nil {
		return nil, false, err
	}
	switch code {
	case http.StatusOK:
		return b, true, nil
	case http.StatusNotFound:
		return nil, false, nil
	}
	return nil, false, agentErr(code, b)
}

func (d *agentDriver) Write(ctx context.Context, content []byte) error {
	code, b, err := d.do(ctx, http.MethodPut, "/v1/file", url.Values{"path": {d.file}}, "application/octet-stream", content)
	if err != nil {
		return err
	}
	if code != http.StatusNoContent && code != http.StatusOK {
		return agentErr(code, b)
	}
	return nil
}

func (d *agentDriver) Reload(ctx context.Context) error {
	if d.reload == "" {
		return errNoReload
	}
	req, _ := json.Marshal(map[string]string{"name": d.reload})
	code, b, err := d.do(ctx, http.MethodPost, "/v1/reload", nil, "application/json", req)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return agentErr(code, b)
	}
	var res reloadResult
	if err := json.Unmarshal(b, &res); err != nil {
		return errors.New("unexpected reload response from agent")
	}
	if out := strings.TrimSpace(res.Output); out != "" {
		fmt.Fprintf(os.Stderr, "    %s\n", out)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("reload %q exited with %d", d.reload, res.ExitCode)
	}
	return nil
}
