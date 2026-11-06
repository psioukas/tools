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

func (c *cliResolver) VW(item, field string) (string, error) { return c.bw.Read(item, field) }

func (c *cliResolver) VWGen(item, field string, n int, cs string) (string, error) {
	if v, err := c.bw.Read(item, field); err == nil && v != "" {
		return v, nil
	} else if err != nil && err != errNotFound && !strings.Contains(err.Error(), "no field") {
		return "", err
	}
	set, _ := charsetFor(cs)
	v, err := generate(n, set)
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
	if len(args) > 0 {
		switch args[0] {
		case "push":
			os.Exit(runPush(args[1:]))
		case "pull":
			os.Exit(runPull(args[1:]))
		case "setup":
			os.Exit(runSetup())
		}
	}
	isNew := len(args) > 0 && args[0] == "new"
	if isNew {
		args = args[1:]
	}
	fs := flag.NewFlagSet("env-gen", flag.ExitOnError)
	force := fs.Bool("force", false, "overwrite existing output files")
	dry := fs.Bool("dry-run", false, "render to stdout, write nothing, store nothing in the vault")
	outFile := fs.String("o", ".env", "output file for -set / new")
	var sets multiFlag
	fs.Var(&sets, "set", "KEY=VALUE entry (repeatable); value may contain placeholders")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage); fs.PrintDefaults() }
	fs.Parse(args)

	res := &cliResolver{bw: NewBw(), in: bufio.NewReader(os.Stdin), dryRun: *dry}

	switch {
	case isNew:
		os.Exit(runNew(res, *outFile, *force, *dry))
	case len(sets) > 0:
		fmt.Fprintf(os.Stderr, "(inline) -> %s\n", *outFile)
		content, err := renderLines(sets, res)
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
			if rendered, err = RenderTemplate(string(src), res); err == nil {
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
