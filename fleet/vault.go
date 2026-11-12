package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
)

var errItemMissing = errors.New("vault item not found")

// vaultClient reaches Vaultwarden through env-gen (`env-gen vault get|set`, `env-gen keys rm`),
// so there is one implementation of vault access, session handling and unlocking.
type vaultClient struct {
	bin   string
	cache map[string]map[string]string
}

func newVault() *vaultClient {
	bin := os.Getenv("FLEET_ENVGEN")
	if bin == "" {
		bin = "env-gen"
	}
	return &vaultClient{bin: bin, cache: map[string]map[string]string{}}
}

func (v *vaultClient) get(item string) (map[string]string, error) {
	if m, ok := v.cache[item]; ok {
		return m, nil
	}
	cmd := exec.Command(v.bin, "vault", "get", item)
	cmd.Stdin = os.Stdin // lets env-gen prompt to unlock when the vault is locked
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 3 {
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

func (v *vaultClient) set(item string, vals map[string]string) error {
	b, _ := json.Marshal(vals)
	cmd := exec.Command(v.bin, "vault", "set", "-force", item)
	cmd.Stdin = bytes.NewReader(b)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("env-gen vault set %q failed: %w", item, err)
	}
	delete(v.cache, item)
	return nil
}

func (v *vaultClient) remove(item string, keys []string) error {
	args := append([]string{"keys", "rm", "-y", item}, keys...)
	cmd := exec.Command(v.bin, args...)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("env-gen keys rm %q failed: %w", item, err)
	}
	delete(v.cache, item)
	return nil
}
