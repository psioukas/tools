package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
)

var errItemMissing = errors.New("vault item not found")

// vaultClient reaches Vaultwarden through env-gen (`env-gen vault get|set`, `env-gen keys rm`),
// so there is one implementation of vault access, session handling and unlocking.
type vaultClient struct {
	bin     string
	mu      sync.Mutex
	cache   map[string]map[string]string
	missing map[string]bool
	env     []string // extra environment for env-gen (the web UI passes BW_SESSION here)
}

func newVault() *vaultClient {
	bin := os.Getenv("FLEET_ENVGEN")
	if bin == "" {
		bin = "env-gen"
	}
	return &vaultClient{bin: bin, cache: map[string]map[string]string{}, missing: map[string]bool{}}
}

func (v *vaultClient) command(args ...string) *exec.Cmd {
	cmd := exec.Command(v.bin, args...)
	if len(v.env) > 0 {
		cmd.Env = append(os.Environ(), v.env...)
	}
	return cmd
}

// get returns an item's variables. Results (and "does not exist") are cached for the
// lifetime of the client, and lookups are serialized so an unlock prompt appears once.
func (v *vaultClient) get(item string) (map[string]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if m, ok := v.cache[item]; ok {
		return m, nil
	}
	if v.missing[item] {
		return nil, errItemMissing
	}
	cmd := v.command("vault", "get", item)
	if len(v.env) == 0 {
		cmd.Stdin = os.Stdin // CLI use: lets env-gen prompt to unlock when the vault is locked
	}
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 3 {
			v.missing[item] = true
			return nil, errItemMissing
		}
		return nil, fmt.Errorf("env-gen vault get %q failed: %w", item, err)
	}
	m := map[string]string{}
	if err := json.Unmarshal(out, &m); err != nil {
		return nil, fmt.Errorf("unexpected output from env-gen: %w", err)
	}
	v.cache[item] = m
	return m, nil
}

func (v *vaultClient) forget(item string) {
	v.mu.Lock()
	delete(v.cache, item)
	delete(v.missing, item)
	v.mu.Unlock()
}

func (v *vaultClient) set(item string, vals map[string]string) error {
	b, _ := json.Marshal(vals)
	cmd := v.command("vault", "set", "-force", item)
	cmd.Stdin = bytes.NewReader(b)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("env-gen vault set %q failed: %w", item, err)
	}
	v.forget(item)
	return nil
}

func (v *vaultClient) remove(item string, keys []string) error {
	args := append([]string{"keys", "rm", "-y", item}, keys...)
	cmd := v.command(args...)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("env-gen keys rm %q failed: %w", item, err)
	}
	v.forget(item)
	return nil
}
