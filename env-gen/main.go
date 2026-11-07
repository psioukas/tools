// env-gen renders .env files from templates, pulling or generating secrets via Vaultwarden (bw CLI).
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type cliResolver struct {
	bw     *Bw
	in     *bufio.Reader
	dryRun bool
}

func (c *cliResolver) VW(item, field string) (string, error) {
	if offline {
		return "", fmt.Errorf("vault access is disabled in offline mode")
	}
	recordItem(item, field)
	return c.bw.Read(item, field)
}

func (c *cliResolver) VWGen(item, field string, n int, cs string) (string, error) {
	recordItem(item, field)
	if offline { // one-time value: generated locally, never stored
		fmt.Fprintf(os.Stderr, "  offline: generated %s/%s locally, not stored\n", item, field)
		return genSecret(n, cs)
	}
	if v, err := c.bw.Read(item, field); err == nil && v != "" {
		return v, nil
	} else if err != nil && err != errNotFound && !strings.Contains(err.Error(), "no field") {
		return "", err
	}
	v, err := genSecret(n, cs)
	if err != nil {
		return "", err
	}
	if c.dryRun {
		fmt.Fprintf(os.Stderr, "  [dry-run] would store new secret in %q/%s\n", item, field)
		return v, nil
	}
	if err := c.bw.Store(item, field, v); err != nil {
		return "", fmt.Errorf("storing in vault: %w", err)
	}
	fmt.Fprintf(os.Stderr, "  stored new secret in vault: %s/%s\n", item, field)
	return v, nil
}

func (c *cliResolver) Prompt(label string) (string, error) {
	fmt.Fprintf(os.Stderr, "  %s: ", label)
	line, err := c.in.ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("no input for prompt %q", label)
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func findTemplates(args []string) ([]string, error) {
	var out []string
	for _, a := range args {
		st, err := os.Stat(a)
		if err != nil {
			return nil, err
		}
		if !st.IsDir() {
			out = append(out, a)
			continue
		}
		err = filepath.WalkDir(a, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules") {
				return filepath.SkipDir
			}
			if !d.IsDir() && strings.HasSuffix(d.Name(), ".env.template") {
				out = append(out, p)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// outputPath: foo/.env.template -> foo/.env ; foo/app.env.template -> foo/app.env
func outputPath(tpl string) string {
	dir, base := filepath.Split(tpl)
	base = strings.TrimSuffix(base, ".template")
	return filepath.Join(dir, base)
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

const usage = `usage:
  env-gen [flags] <template|dir>...        render *.env.template files
  env-gen [flags] -set KEY=VALUE ... [-o FILE]   build an env with no template
  env-gen new [-o FILE] [-force] [-dry-run]      interactive builder (TUI)
  env-gen edit [FILE] [-set K=V]... [-unset K]...   edit an existing .env (menu, or flags to script it)
  env-gen ui init | ui -root DIR -host H -trust-proxy   web UI (behind your HTTPS reverse proxy)
  env-gen completion bash|zsh|fish|install       shell auto-completion
  env-gen unlock | lock                          unlock the vault (session cached briefly) / clear it
  env-gen keys list|show|rm|rename|rotate ...    manage the fields stored in a vault item
  env-gen cache [list|clear|path]                recently used vault item/field names (no secrets)
  env-gen config [list|path|get K|set K V|unset K]   settings file in your user config dir
  env-gen setup                                  guided bw setup: server URL, login, unlock, connection test
  env-gen push [-item NAME] <.env>               store an existing .env in the vault + write a template
  env-gen pull [-o FILE] <vault item>            write a .env from a vault item's custom fields

Renders each *.env.template (directories are searched recursively) to the
sibling .env file (mode 0600). Placeholders (also valid in -set values):

  {{gen:N[:alnum|hex|symbols]}}      random value
  {{prompt:Label}}                   ask interactively
  {{vw:Item/field}}                  read from Vaultwarden (field: password|username|uri|notes|<custom>)
  {{vwgen:Item/field:N[:charset]}}   read from Vaultwarden, or generate and store if missing

Needs the bw CLI logged in to your Vaultwarden server and
BW_SESSION exported (export BW_SESSION="$(bw unlock --raw)").

flags:
`

// writeEnv writes content to path (0600), honouring -force / -dry-run.
func writeEnv(path, content string, force, dry bool) error {
	if dry {
		fmt.Printf("# --- %s ---\n%s", path, content)
		return nil
	}
	if _, err := os.Stat(path); err == nil && !force {
		fmt.Fprintln(os.Stderr, "  skipped: exists (use -force)")
		return nil
	}
	return os.WriteFile(path, []byte(content), 0o600)
}

func main() {
	args := os.Args[1:]
	if c, err := LoadConfig(); err != nil {
		fmt.Fprintln(os.Stderr, "warning: ignoring config:", err)
	} else {
		cfg = c
	}
	if len(args) > 0 {
		switch args[0] {
		case "config":
			os.Exit(runConfig(args[1:]))
		case "push":
			os.Exit(runPush(args[1:]))
		case "pull":
			os.Exit(runPull(args[1:]))
		case "ui":
			os.Exit(runUI(args[1:]))
		case "completion":
			os.Exit(runCompletion(args[1:]))
		case "__complete":
			os.Exit(runComplete(args[1:]))
		case "keys":
			os.Exit(runKeys(args[1:]))
		case "unlock":
			os.Exit(runUnlock())
		case "lock":
			os.Exit(runLock())
		case "cache":
			os.Exit(runCache(args[1:]))
		case "setup":
			os.Exit(runSetup())
		}
	}
	isNew := len(args) > 0 && args[0] == "new"
	isEdit := len(args) > 0 && args[0] == "edit"
	if isNew || isEdit {
		args = args[1:]
	}
	fs := flag.NewFlagSet("env-gen", flag.ExitOnError)
	force := fs.Bool("force", false, "overwrite existing output files")
	dry := fs.Bool("dry-run", false, "render to stdout, write nothing, store nothing in the vault")
	outFile := fs.String("o", cfg.Get("defaults.output", ".env"), "output file for -set / new")
	from := fs.String("from", "", "example file for new (default: auto-detect .env.example)")
	blank := fs.Bool("blank", false, "for new: ignore any example file")
	backup := fs.String("backup", "", "also store every rendered variable in this vault item (template / -set modes)")
	offlineFlag := fs.Bool("offline", false, "one-time mode: no vault access, secrets generated locally with bw generate, nothing stored")
	genFlag := fs.String("generator", cfg.Get("defaults.generator", "builtin"), "secret generator: builtin | bw (Bitwarden password generator)")
	var sets, unsets multiFlag
	fs.Var(&unsets, "unset", "KEY to remove (edit mode, repeatable)")
	fs.Var(&sets, "set", "KEY=VALUE entry (repeatable); value may contain placeholders")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage); fs.PrintDefaults() }
	fs.Parse(args)

	offline, generatorMode = *offlineFlag, *genFlag
	if generatorMode != "builtin" && generatorMode != "bw" {
		fmt.Fprintln(os.Stderr, "error: -generator must be builtin or bw")
		os.Exit(2)
	}
	if offline {
		generatorMode = "bw"
		if *backup != "" {
			fmt.Fprintln(os.Stderr, "error: -backup needs the vault; it can't be combined with -offline")
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "offline mode: values are generated locally and NOT stored anywhere; keep the output file safe.")
	}
	res := &cliResolver{bw: NewBw(), in: bufio.NewReader(os.Stdin), dryRun: *dry}

	switch {
	case isEdit:
		file := ".env"
		if fs.NArg() > 0 {
			file = fs.Arg(0)
		}
		os.Exit(runEdit(res, file, sets, unsets, *backup, *dry))
	case isNew:
		os.Exit(runNew(res, *outFile, *force, *dry, *from, *blank))
	case len(sets) > 0:
		fmt.Fprintf(os.Stderr, "(inline) -> %s\n", *outFile)
		content, err := renderLines(sets, res)
		if err == nil && *backup != "" {
			err = backupContent(res.bw, *backup, content, *dry)
		}
		if err == nil {
			err = writeEnv(*outFile, content, *force, *dry)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "  error:", err)
			os.Exit(1)
		}
		return
	case fs.NArg() == 0:
		fs.Usage()
		os.Exit(2)
	}

	tpls, err := findTemplates(fs.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if len(tpls) == 0 {
		fmt.Fprintln(os.Stderr, "no templates found")
		os.Exit(1)
	}
	failed := 0
	for _, t := range tpls {
		out := outputPath(t)
		fmt.Fprintf(os.Stderr, "%s -> %s\n", t, out)
		src, err := os.ReadFile(t)
		if err == nil {
			var rendered string
			if rendered, err = RenderTemplate(string(src), res); err == nil && *backup != "" {
				err = backupContent(res.bw, *backup, rendered, *dry)
			}
			if err == nil {
				err = writeEnv(out, rendered, *force, *dry)
			}
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "  error:", err)
			failed++
		}
	}
	if failed > 0 {
		os.Exit(1)
	}
}
