package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// runPush stores every variable of an existing .env as a hidden custom field of
// one vault item and writes a template that references them.
func runPush(args []string) int {
	fs := flag.NewFlagSet("push", flag.ExitOnError)
	item := fs.String("item", "", "vault item name (default: <project dir>)")
	force := fs.Bool("force", false, "overwrite existing fields / template")
	dry := fs.Bool("dry-run", false, "show what would happen, change nothing")
	noTpl := fs.Bool("no-template", false, "don't write a .env.template")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: env-gen push [flags] <path/to/.env>")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	path := fs.Arg(0)
	pairs, err := parseEnv(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if len(pairs) == 0 {
		fmt.Fprintln(os.Stderr, "no variables found")
		return 1
	}
	if *item == "" {
		abs, _ := filepath.Abs(path)
		*item = filepath.Base(filepath.Dir(abs))
	}
	var tpl strings.Builder
	for _, p := range pairs {
		fmt.Fprintf(&tpl, "%s={{vw:%s/%s}}\n", p.Key, *item, p.Key)
	}
	tplPath := path + ".template"
	fmt.Fprintf(os.Stderr, "%d variables -> vault item %q\n", len(pairs), *item)
	if *dry {
		for _, p := range pairs {
			fmt.Fprintf(os.Stderr, "  would store %s\n", p.Key)
		}
		fmt.Fprintf(os.Stderr, "  would write %s\n", tplPath)
		return 0
	}
	if err := NewBw().StoreFields(*item, pairs, *force, false); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if !*noTpl {
		if err := writeEnv(tplPath, tpl.String(), *force, false); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "wrote template %s\n", tplPath)
	}
	fmt.Fprintln(os.Stderr, "done. Verify with `env-gen pull`, then you can delete the plaintext .env if it's not needed.")
	return 0
}

// runPull writes a .env straight from a vault item's custom fields.
func runPull(args []string) int {
	fs := flag.NewFlagSet("pull", flag.ExitOnError)
	out := fs.String("o", ".env", "output file")
	force := fs.Bool("force", false, "overwrite an existing output file")
	dry := fs.Bool("dry-run", false, "print to stdout instead of writing")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: env-gen pull [flags] <vault item>")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	bw := NewBw()
	fields, err := bw.Fields(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	var sb strings.Builder
	for _, f := range fields {
		if !keyRe.MatchString(f.Name) {
			fmt.Fprintf(os.Stderr, "  skipped field %q (not a valid variable name)\n", f.Name)
			continue
		}
		sb.WriteString(f.Name + "=" + quoteIfNeeded(f.Value) + "\n")
	}
	if sb.Len() == 0 {
		fmt.Fprintln(os.Stderr, "item has no usable custom fields")
		return 1
	}
	fmt.Fprintf(os.Stderr, "%s -> %s\n", fs.Arg(0), *out)
	if err := writeEnv(*out, sb.String(), *force, *dry); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

// backupContent mirrors every variable of a rendered env file into one vault
// item as hidden custom fields (existing fields are updated), so the vault
// always holds a copy of what was written.
func backupContent(bw *Bw, item, content string, dry bool) error {
	pairs, err := parseEnvReader(strings.NewReader(content), "rendered env")
	if err != nil {
		return err
	}
	if len(pairs) == 0 {
		return nil
	}
	if dry {
		fmt.Fprintf(os.Stderr, "  [dry-run] would back up %d variables to vault item %q\n", len(pairs), item)
		return nil
	}
	if err := bw.StoreFields(item, pairs, true, false); err != nil {
		return fmt.Errorf("vault backup to %q: %w", item, err)
	}
	fmt.Fprintf(os.Stderr, "  backed up %d variables to vault item %q\n", len(pairs), item)
	return nil
}
