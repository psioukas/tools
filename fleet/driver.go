package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Driver is the plug-in point: one implementation per kind of target. To support a
// new kind of machine or store, implement this interface and add it to `registry`.
type Driver interface {
	// Describe is the human-readable location, e.g. "deploy@10.0.0.12:/srv/shop/.env".
	Describe() string
	// Read returns the current env file. exists is false when it isn't there yet.
	Read(ctx context.Context) (content []byte, exists bool, err error)
	// Write replaces the env file atomically, keeping the previous one as FILE.bak.
	Write(ctx context.Context, content []byte) error
	// Reload makes the app pick up the new values (restart, recreate, ...).
	Reload(ctx context.Context) error
}

// RuntimeChecker is optional: drivers that can see the running app report variables
// whose live value differs from `want` (names only), so a push without reload is noticed.
type RuntimeChecker interface {
	RuntimeDiffers(ctx context.Context, want map[string]string) ([]string, error)
}

var registry = map[string]func(*Target) (Driver, error){
	"file":   newFileDriver,
	"ssh":    newSSHDriver,
	"docker": newDockerDriver,
}

func newDriver(t *Target) (Driver, error) {
	f, ok := registry[t.Driver]
	if !ok {
		return nil, fmt.Errorf("unknown driver %q", t.Driver)
	}
	return f(t)
}

var errNoReload = errors.New("no reload command configured for this target")

// store is where an env file lives plus a way to run commands next to it.
type store interface {
	where(path string) string
	read(ctx context.Context, path string) ([]byte, bool, error)
	write(ctx context.Context, path string, content []byte) error
	shell(ctx context.Context, cmd string) ([]byte, error)
}

// ---- local ----------------------------------------------------------------------------------

type localStore struct{}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}

func (localStore) where(p string) string { return expandHome(p) }

func (localStore) read(_ context.Context, p string) ([]byte, bool, error) {
	b, err := os.ReadFile(expandHome(p))
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	return b, err == nil, err
}

func (localStore) write(_ context.Context, p string, content []byte) error {
	p = expandHome(p)
	dir := filepath.Dir(p)
	mode := os.FileMode(0o600)
	if old, err := os.ReadFile(p); err == nil {
		if st, err := os.Stat(p); err == nil {
			mode = st.Mode().Perm()
		}
		if err := os.WriteFile(p+".bak", old, mode); err != nil {
			return fmt.Errorf("writing backup: %w", err)
		}
	}
	tmp, err := os.CreateTemp(dir, ".fleet-*")
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
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}

func (localStore) shell(ctx context.Context, cmd string) ([]byte, error) {
	return runCmd(ctx, nil, "sh", "-c", cmd)
}

// ---- ssh ------------------------------------------------------------------------------------------

type sshStore struct {
	bin, host, identity string
	port                int
}

func newSSHStore(host, identity string, port int) *sshStore {
	bin := os.Getenv("FLEET_SSH")
	if bin == "" {
		bin = "ssh"
	}
	return &sshStore{bin: bin, host: host, identity: identity, port: port}
}

func (s *sshStore) where(p string) string { return s.host + ":" + p }

func (s *sshStore) args(script string) []string {
	a := []string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=10"}
	if s.port != 0 {
		a = append(a, "-p", fmt.Sprint(s.port))
	}
	if s.identity != "" {
		a = append(a, "-i", expandHome(s.identity))
	}
	return append(a, s.host, script)
}

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// remotePath quotes a path for a remote POSIX shell and expands a leading ~ to $HOME.
func remotePath(p string) string {
	switch {
	case p == "~":
		return `"$HOME"`
	case strings.HasPrefix(p, "~/"):
		return `"$HOME"/` + shQuote(strings.TrimPrefix(p, "~/"))
	}
	return shQuote(p)
}

const exitMissing = 44

func (s *sshStore) read(ctx context.Context, p string) ([]byte, bool, error) {
	out, err := runCmd(ctx, nil, s.bin, s.args(`f=`+remotePath(p)+`; [ -f "$f" ] || exit 44; cat "$f"`)...)
	var ee *exitError
	if errors.As(err, &ee) && ee.code == exitMissing {
		return nil, false, nil
	}
	return out, err == nil, err
}

func (s *sshStore) write(ctx context.Context, p string, content []byte) error {
	script := `set -e; umask 077; f=` + remotePath(p) + `; t="$f.fleet.$$"; trap 'rm -f "$t"' EXIT; cat > "$t"; ` +
		`if [ -f "$f" ]; then cp -p "$f" "$f.bak"; chmod --reference="$f" "$t" 2>/dev/null || true; fi; mv "$t" "$f"`
	_, err := runCmd(ctx, content, s.bin, s.args(script)...)
	return err
}

func (s *sshStore) shell(ctx context.Context, cmd string) ([]byte, error) {
	return runCmd(ctx, nil, s.bin, s.args(cmd)...)
}

// ---- command runner -----------------------------------------------------------------------------

type exitError struct {
	code   int
	stderr string
}

func (e *exitError) Error() string {
	if e.stderr != "" {
		return fmt.Sprintf("exit %d: %s", e.code, e.stderr)
	}
	return fmt.Sprintf("exit %d", e.code)
}

func runCmd(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			msg := strings.TrimSpace(errb.String())
			if len(msg) > 400 {
				msg = msg[:400] + "..."
			}
			return out.Bytes(), &exitError{ee.ExitCode(), msg}
		}
		return out.Bytes(), err
	}
	return out.Bytes(), nil
}

// ---- drivers built on a store ---------------------------------------------------------------------

type storeDriver struct {
	st     store
	file   string
	reload string
}

func (d *storeDriver) Describe() string { return d.st.where(d.file) }

func (d *storeDriver) Read(ctx context.Context) ([]byte, bool, error) {
	return d.st.read(ctx, d.file)
}

func (d *storeDriver) Write(ctx context.Context, c []byte) error { return d.st.write(ctx, d.file, c) }

func (d *storeDriver) Reload(ctx context.Context) error {
	if d.reload == "" {
		return errNoReload
	}
	out, err := d.st.shell(ctx, d.reload)
	if len(out) > 0 {
		fmt.Fprintf(os.Stderr, "    %s\n", strings.TrimSpace(string(out)))
	}
	return err
}

func newFileDriver(t *Target) (Driver, error) {
	return &storeDriver{st: localStore{}, file: t.File, reload: t.Reload}, nil
}

func newSSHDriver(t *Target) (Driver, error) {
	return &storeDriver{st: newSSHStore(t.Host, t.Identity, t.Port), file: t.File, reload: t.Reload}, nil
}

type dockerDriver struct {
	storeDriver
	container, context string
}

func newDockerDriver(t *Target) (Driver, error) {
	var st store = localStore{}
	if t.Host != "" {
		st = newSSHStore(t.Host, t.Identity, t.Port)
	}
	d := &dockerDriver{storeDriver: storeDriver{st: st, file: t.File, reload: t.Reload}, container: t.Container, context: t.Context}
	if d.reload == "" {
		ctxFlag := ""
		if t.Host == "" && t.Context != "" {
			ctxFlag = " --context " + shQuote(t.Context)
		}
		switch {
		case t.Service != "":
			// restart alone would keep the old env_file values; recreate re-reads them
			d.reload = "docker" + ctxFlag + " compose --project-directory " + shQuote(t.ComposeDir) + " up -d --force-recreate " + shQuote(t.Service)
		case t.Container != "":
			d.reload = "docker" + ctxFlag + " restart " + shQuote(t.Container)
		}
	}
	return d, nil
}

// RuntimeDiffers compares the running container's environment with what a push would write.
func (d *dockerDriver) RuntimeDiffers(ctx context.Context, want map[string]string) ([]string, error) {
	if d.container == "" {
		return nil, nil
	}
	ctxFlag := ""
	if _, local := d.st.(localStore); local && d.context != "" {
		ctxFlag = " --context " + shQuote(d.context)
	}
	out, err := d.st.shell(ctx, "docker"+ctxFlag+" inspect -f '{{json .Config.Env}}' "+shQuote(d.container))
	if err != nil {
		return nil, err
	}
	var env []string
	if err := json.Unmarshal(bytes.TrimSpace(out), &env); err != nil {
		return nil, fmt.Errorf("unexpected docker inspect output")
	}
	live := map[string]string{}
	for _, e := range env {
		if k, v, ok := strings.Cut(e, "="); ok {
			live[k] = v
		}
	}
	var diff []string
	for _, k := range sortedKeys(want) {
		if lv, ok := live[k]; !ok || lv != want[k] {
			diff = append(diff, k)
		}
	}
	return diff, nil
}
