package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"gopkg.in/yaml.v3"
)

// Config is apps.yaml: names and wiring only. It is safe to commit because it never
// holds a secret value; values come from the vault (plus non-secret overrides).
type Config struct {
	Apps map[string]*App `yaml:"apps"`
	path string
}

type App struct {
	VaultItem string             `yaml:"vault_item"` // default item holding this app's variables
	Exclude   []string           `yaml:"exclude"`    // keys never sent to any target
	Targets   map[string]*Target `yaml:"targets"`
}

type Target struct {
	Driver    string            `yaml:"driver"` // file | ssh | docker
	File      string            `yaml:"file"`   // path of the env file (on the host for ssh/docker+host)
	Host      string            `yaml:"host"`   // ssh destination (user@host or an alias from ~/.ssh/config)
	Port      int               `yaml:"port"`
	Identity  string            `yaml:"identity"`
	VaultItem string            `yaml:"vault_item"` // overrides the app's item (e.g. shop-prod)
	Include   []string          `yaml:"include"`    // if set, only these keys
	Exclude   []string          `yaml:"exclude"`
	Overrides map[string]string `yaml:"overrides"` // literal, non-secret per-target values
	Reload    string            `yaml:"reload"`    // command run after a push when -reload is given

	// docker driver
	Container  string `yaml:"container"`
	Context    string `yaml:"context"` // docker context for local docker commands
	ComposeDir string `yaml:"compose_dir"`
	Service    string `yaml:"service"`

	// agent driver (the token itself never goes in apps.yaml)
	AgentURL         string `yaml:"agent_url"`
	AgentFingerprint string `yaml:"agent_fingerprint"`
	AgentTokenEnv    string `yaml:"agent_token_env"`
	AgentTokenFile   string `yaml:"agent_token_file"`

	app, name string
}

var keyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func configPath(flagPath string) string {
	if flagPath != "" {
		return flagPath
	}
	if p := os.Getenv("FLEET_CONFIG"); p != "" {
		return p
	}
	if _, err := os.Stat("apps.yaml"); err == nil {
		return "apps.yaml"
	}
	if dir, err := os.UserConfigDir(); err == nil {
		p := filepath.Join(dir, "fleet", "apps.yaml")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "apps.yaml"
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w (create one with `fleet init`)", err)
	}
	var c Config
	dec := yaml.NewDecoder(bytesReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.path = path
	if len(c.Apps) == 0 {
		return nil, fmt.Errorf("%s: no apps defined", path)
	}
	for an, a := range c.Apps {
		if a == nil || len(a.Targets) == 0 {
			return nil, fmt.Errorf("app %q has no targets", an)
		}
		if a.VaultItem == "" {
			a.VaultItem = an
		}
		for tn, t := range a.Targets {
			if t == nil {
				return nil, fmt.Errorf("%s/%s: empty target", an, tn)
			}
			t.app, t.name = an, tn
			if err := t.validate(); err != nil {
				return nil, fmt.Errorf("%s/%s: %w", an, tn, err)
			}
		}
	}
	return &c, nil
}

func (t *Target) validate() error {
	if t.File == "" {
		return fmt.Errorf("`file` is required")
	}
	switch t.Driver {
	case "file":
		if t.Host != "" {
			return fmt.Errorf("driver file is local; use driver ssh for host %q", t.Host)
		}
	case "ssh":
		if t.Host == "" {
			return fmt.Errorf("driver ssh needs `host`")
		}
	case "docker":
		if t.Container == "" && t.Service == "" && t.Reload == "" {
			return fmt.Errorf("driver docker needs `container`, `service` (with compose_dir) or `reload`")
		}
		if t.Service != "" && t.ComposeDir == "" {
			return fmt.Errorf("`service` needs `compose_dir`")
		}
	case "agent":
		if err := t.validateAgent(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown driver %q (file | ssh | docker | agent)", t.Driver)
	}
	for k := range t.Overrides {
		if !keyRe.MatchString(k) {
			return fmt.Errorf("override %q is not a valid variable name", k)
		}
	}
	return nil
}

func (c *Config) appNames() []string {
	var n []string
	for k := range c.Apps {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

func (a *App) targetNames() []string {
	var n []string
	for k := range a.Targets {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

// item is the vault item a target takes its values from.
func (t *Target) item(a *App) string {
	if t.VaultItem != "" {
		return t.VaultItem
	}
	return a.VaultItem
}

const sampleConfig = `# fleet inventory: names and wiring only, safe to commit. Secret values live in Vaultwarden.
apps:
  shop:
    vault_item: shop            # default item holding this app's variables
    exclude: [LOCAL_ONLY]       # keys never sent anywhere
    targets:
      prod-vm:
        driver: ssh
        host: deploy@10.0.0.12  # anything ssh accepts, including ~/.ssh/config aliases
        file: /srv/shop/.env
        vault_item: shop-prod   # this target takes its values from another item
        overrides: { APP_ENV: production }
        reload: docker compose --project-directory /srv/shop up -d --force-recreate
      staging:
        driver: docker
        file: /srv/shop/.env
        host: staging           # docker files and commands run on this host over ssh
        container: shop-web
        compose_dir: /srv/shop
        service: web
      laptop:
        driver: file
        file: ~/projects/shop/.env
`

func cmdInit(args []string) int {
	path := "apps.yaml"
	if len(args) > 0 {
		path = args[0]
	}
	if _, err := os.Stat(path); err == nil {
		fmt.Fprintf(os.Stderr, "%s already exists\n", path)
		return 1
	}
	if err := os.WriteFile(path, []byte(sampleConfig), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "wrote %s: edit it to match your apps and machines\n", path)
	return 0
}
