package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
)

// rawItem fetches an item as untyped JSON so edits keep everything we don't model.
func (b *Bw) rawItem(name string) (map[string]any, error) {
	if err := b.Ready(); err != nil {
		return nil, err
	}
	out, err := b.run("", "get", "item", name)
	if err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := jsonUnmarshal(out, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func (b *Bw) saveRaw(raw map[string]any) error {
	delete(b.cache, fmt.Sprint(raw["name"]))
	return b.editRaw(raw)
}

func rawFields(raw map[string]any) []map[string]any {
	var out []map[string]any
	fs, _ := raw["fields"].([]any)
	for _, f := range fs {
		if m, ok := f.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func setRawFields(raw map[string]any, fs []map[string]any) {
	arr := make([]any, len(fs))
	for i, f := range fs {
		arr[i] = f
	}
	raw["fields"] = arr
}

func confirmYes(prompt string, yes bool) bool {
	if yes {
		return true
	}
	if !isTerminal(os.Stdin) {
		fmt.Fprintln(os.Stderr, "refusing without a terminal; pass -y to confirm")
		return false
	}
	fmt.Fprintf(os.Stderr, "%s [y/N] ", prompt)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "y")
}

func keysUsage() int {
	fmt.Fprint(os.Stderr, `usage: env-gen keys <command>

  list [ITEM]                     fields stored in a vault item (default: this folder's name), values masked
  show ITEM KEY                   print one value
  rm [-y] ITEM KEY...             delete fields
  rename ITEM OLD NEW             rename a field
  rotate [-y] [-length N] [-charset alnum|hex|symbols] ITEM KEY
                                  replace a field with a fresh random value
  recent                          vault items used recently (same as 'cache list')

A rotated or removed value is not changed in .env files already written; re-run
'env-gen pull ITEM' (or edit) to update them.
`)
	return 2
}

func runKeys(args []string) int {
	if len(args) == 0 {
		args = []string{"list"}
	}
	cmd, rest := args[0], args[1:]
	bw := NewBw()
	switch cmd {
	case "recent":
		return runCache([]string{"list"})
	case "list":
		item := projectName()
		if len(rest) > 0 {
			item = rest[0]
		}
		raw, err := bw.rawItem(item)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		recordItem(item)
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "FIELD\tTYPE\tVALUE")
		for _, f := range rawFields(raw) {
			typ := "text"
			if t, _ := f["type"].(float64); t == 1 {
				typ = "hidden"
			}
			v := fmt.Sprint(f["value"])
			fmt.Fprintf(tw, "%v\t%s\t(%d chars)\n", f["name"], typ, len(v))
		}
		tw.Flush()
	case "show":
		if len(rest) != 2 {
			return keysUsage()
		}
		v, err := bw.Read(rest[0], rest[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		recordItem(rest[0], rest[1])
		fmt.Println(v)
	case "rm", "rename", "rotate":
		return keysMutate(bw, cmd, rest)
	default:
		return keysUsage()
	}
	return 0
}

func keysMutate(bw *Bw, cmd string, args []string) int {
	fs := flag.NewFlagSet("keys "+cmd, flag.ExitOnError)
	yes := fs.Bool("y", false, "don't ask for confirmation")
	length := fs.Int("length", 32, "rotate: new secret length")
	charset := fs.String("charset", "alnum", "rotate: alnum|hex|symbols")
	fs.Parse(args)
	pos := fs.Args()
	if len(pos) < 2 || (cmd == "rename" && len(pos) != 3) || (cmd == "rotate" && len(pos) != 2) {
		return keysUsage()
	}
	item := pos[0]
	raw, err := bw.rawItem(item)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fields := rawFields(raw)
	idx := func(name string) int {
		for i, f := range fields {
			if f["name"] == name {
				return i
			}
		}
		return -1
	}
	switch cmd {
	case "rm":
		drop := map[string]bool{}
		for _, k := range pos[1:] {
			if idx(k) < 0 {
				fmt.Fprintf(os.Stderr, "error: item %q has no field %q\n", item, k)
				return 1
			}
			drop[k] = true
		}
		if !confirmYes(fmt.Sprintf("Delete %d field(s) from %q?", len(drop), item), *yes) {
			return 1
		}
		var keep []map[string]any
		for _, f := range fields {
			if !drop[fmt.Sprint(f["name"])] {
				keep = append(keep, f)
			}
		}
		setRawFields(raw, keep)
	case "rename":
		old, nw := pos[1], pos[2]
		if !keyRe.MatchString(nw) {
			fmt.Fprintln(os.Stderr, "error: new name must look like an env var name")
			return 1
		}
		i := idx(old)
		if i < 0 || idx(nw) >= 0 {
			fmt.Fprintf(os.Stderr, "error: %q must exist and %q must not\n", old, nw)
			return 1
		}
		fields[i]["name"] = nw
		setRawFields(raw, fields)
	case "rotate":
		i := idx(pos[1])
		if i < 0 {
			fmt.Fprintf(os.Stderr, "error: item %q has no field %q\n", item, pos[1])
			return 1
		}
		if !confirmYes(fmt.Sprintf("Replace %s/%s with a new random value? Existing .env files keep the old one.", item, pos[1]), *yes) {
			return 1
		}
		v, err := genSecret(*length, *charset)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		fields[i]["value"] = v
		setRawFields(raw, fields)
	}
	if err := bw.saveRaw(raw); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	recordItem(item)
	fmt.Fprintf(os.Stderr, "%s: done (%s)\n", item, cmd)
	return 0
}
