package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Config lives in the user's config dir, like ~/.aws/config or ~/.config/git/config:
//
//	Linux/macOS: $XDG_CONFIG_HOME/env-gen/config  (default ~/.config/env-gen/config)
//	Windows:     %AppData%\env-gen\config
//
// Override with ENV_GEN_CONFIG=/path/to/file. It holds settings only, never secrets
// (no master password, no BW_SESSION).
type Config struct {
	Path string
	vals map[string]string
}

// known keys and what they mean (shown by `env-gen config`).
var configKeys = []struct{ Key, Desc string }{
	{"vault.server", "Vaultwarden server URL"},
	{"vault.email", "account email (informational)"},
	{"vault.bw", "path to the bw binary (default: bw from PATH)"},
	{"defaults.output", "default output file for -set / new (default .env)"},
	{"defaults.length", "default generated-secret length in the TUI (default 32)"},
	{"defaults.charset", "default charset in the TUI: alnum|hex|symbols"},
}

func ConfigPath() string {
	if p := os.Getenv("ENV_GEN_CONFIG"); p != "" {
		return p
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "env-gen", "config")
}

func LoadConfig() (*Config, error) {
	c := &Config{Path: ConfigPath(), vals: map[string]string{}}
	if c.Path == "" {
		return c, nil
	}
	f, err := os.Open(c.Path)
	if os.IsNotExist(err) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	defer f.Close()
	section := ""
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || line[0] == '#' || line[0] == ';':
		case line[0] == '[' && line[len(line)-1] == ']':
			section = strings.TrimSpace(line[1 : len(line)-1])
		default:
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				return c, fmt.Errorf("%s:%d: expected key = value", c.Path, n)
			}
			c.vals[section+"."+strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return c, sc.Err()
}

func (c *Config) Get(key, def string) string {
	if v := c.vals[key]; v != "" {
		return v
	}
	return def
}

func (c *Config) Set(key, val string) { c.vals[key] = val }

func (c *Config) Unset(key string) { delete(c.vals, key) }

func (c *Config) Save() error {
	if c.Path == "" {
		return fmt.Errorf("cannot determine config directory (set ENV_GEN_CONFIG)")
	}
	bySection := map[string][]string{}
	for k := range c.vals {
		sec, name, _ := strings.Cut(k, ".")
		bySection[sec] = append(bySection[sec], name)
	}
	secs := make([]string, 0, len(bySection))
	for s := range bySection {
		secs = append(secs, s)
	}
	sort.Strings(secs)
	var sb strings.Builder
	sb.WriteString("# env-gen config. Settings only; never put secrets here.\n")
	for _, s := range secs {
		sort.Strings(bySection[s])
		fmt.Fprintf(&sb, "\n[%s]\n", s)
		for _, k := range bySection[s] {
			fmt.Fprintf(&sb, "%s = %s\n", k, c.vals[s+"."+k])
		}
	}
	if err := os.MkdirAll(filepath.Dir(c.Path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(c.Path, []byte(sb.String()), 0o600)
}

func isKnownKey(k string) bool {
	for _, e := range configKeys {
		if e.Key == k {
			return true
		}
	}
	return false
}

var cfg = &Config{vals: map[string]string{}}

// genDefaults returns the TUI's default length and charset.
func genDefaults() (string, string) {
	n, cs := cfg.Get("defaults.length", "32"), cfg.Get("defaults.charset", "alnum")
	if validLen(n) != nil {
		n = "32"
	}
	if _, err := charsetFor(cs); err != nil {
		cs = "alnum"
	}
	return n, cs
}

// runConfig implements: env-gen config [path|list|get KEY|set KEY VALUE|unset KEY]
func runConfig(args []string) int {
	cmd := "list"
	if len(args) > 0 {
		cmd = args[0]
	}
	switch {
	case cmd == "path":
		fmt.Println(cfg.Path)
	case cmd == "list":
		fmt.Fprintf(os.Stderr, "# %s\n", cfg.Path)
		for _, e := range configKeys {
			fmt.Printf("%-18s = %-34s # %s\n", e.Key, cfg.vals[e.Key], e.Desc)
		}
	case cmd == "get" && len(args) == 2:
		fmt.Println(cfg.vals[args[1]])
	case cmd == "set" && len(args) == 3:
		if !isKnownKey(args[1]) {
			fmt.Fprintf(os.Stderr, "unknown key %q (see `env-gen config list`)\n", args[1])
			return 1
		}
		if args[1] == "defaults.charset" {
			if _, err := charsetFor(args[2]); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
		}
		if args[1] == "defaults.length" && validLen(args[2]) != nil {
			fmt.Fprintln(os.Stderr, "length must be a positive number")
			return 1
		}
		cfg.Set(args[1], args[2])
		if err := cfg.Save(); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
	case cmd == "unset" && len(args) == 2:
		cfg.Unset(args[1])
		if err := cfg.Save(); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
	default:
		fmt.Fprintln(os.Stderr, "usage: env-gen config [list | path | get KEY | set KEY VALUE | unset KEY]")
		return 2
	}
	return 0
}
