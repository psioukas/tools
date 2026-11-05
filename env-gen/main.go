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

func main() {
	force := flag.Bool("force", false, "overwrite existing output files")
	dry := flag.Bool("dry-run", false, "render to stdout, write nothing, store nothing in the vault")
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: env-gen [flags] <template|dir>...

Renders each *.env.template (directories are searched recursively) to the
sibling .env file (mode 0600). Placeholders:

  {{gen:N[:alnum|hex|symbols]}}      random value
  {{prompt:Label}}                   ask interactively
  {{vw:Item/field}}                  read from Vaultwarden (field: password|username|uri|notes|<custom>)
  {{vwgen:Item/field:N[:charset]}}   read from Vaultwarden, or generate and store if missing

Needs the bw CLI logged in to your Vaultwarden server and
BW_SESSION exported (export BW_SESSION="$(bw unlock --raw)").

flags:
`)
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}
	tpls, err := findTemplates(flag.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if len(tpls) == 0 {
		fmt.Fprintln(os.Stderr, "no templates found")
		os.Exit(1)
	}
	res := &cliResolver{bw: NewBw(), in: bufio.NewReader(os.Stdin), dryRun: *dry}
	failed := 0
	for _, t := range tpls {
		out := outputPath(t)
		fmt.Fprintf(os.Stderr, "%s -> %s\n", t, out)
		if _, err := os.Stat(out); err == nil && !*force && !*dry {
			fmt.Fprintln(os.Stderr, "  skipped: exists (use -force)")
			continue
		}
		src, err := os.ReadFile(t)
		if err == nil {
			var rendered string
			rendered, err = Render(string(src), res)
			if err == nil {
				if *dry {
					fmt.Printf("# --- %s ---\n%s\n", out, rendered)
				} else {
					err = os.WriteFile(out, []byte(rendered), 0o600)
				}
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
