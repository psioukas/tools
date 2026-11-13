package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

// runVault is the machine-readable vault interface other tools (fleet) call:
//
//	env-gen vault get ITEM          JSON object {"KEY":"value",...} of the item's custom fields
//	env-gen vault set [-force] ITEM reads that JSON object from stdin and stores each pair as a hidden custom field
//
// Exit status 3 means the item does not exist. Output is JSON only on stdout;
// prompts and errors go to stderr.
func runVault(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: env-gen vault get ITEM | env-gen vault set [-force] ITEM | env-gen vault unlock")
		return 2
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "unlock":
		// For programs that hold the master password themselves (fleet's web UI): the password
		// is read from stdin (one line), the session key is printed to stdout and is NOT cached on disk.
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		pw := strings.TrimRight(line, "\r\n")
		if pw == "" {
			fmt.Fprintln(os.Stderr, "error: no password on stdin")
			return 2
		}
		sess, err := NewBw().Unlock(pw)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: unlock failed:", err)
			return 1
		}
		fmt.Println(sess)
	case "get":
		if len(rest) != 1 {
			fmt.Fprintln(os.Stderr, "usage: env-gen vault get ITEM")
			return 2
		}
		fields, err := NewBw().Fields(rest[0])
		if err != nil {
			if err == errNotFound {
				fmt.Fprintf(os.Stderr, "vault item %q not found\n", rest[0])
				return 3
			}
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		recordItem(rest[0])
		out := map[string]string{}
		for _, f := range fields {
			out[f.Name] = f.Value
		}
		if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
	case "set":
		fs := flag.NewFlagSet("vault set", flag.ExitOnError)
		force := fs.Bool("force", false, "overwrite fields that already exist")
		fs.Parse(rest)
		if fs.NArg() != 1 {
			fmt.Fprintln(os.Stderr, "usage: env-gen vault set [-force] ITEM  (JSON object on stdin)")
			return 2
		}
		var in map[string]string
		if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
			fmt.Fprintln(os.Stderr, "error: expected a JSON object of strings on stdin:", err)
			return 2
		}
		names := make([]string, 0, len(in))
		for k := range in {
			if !keyRe.MatchString(k) {
				fmt.Fprintf(os.Stderr, "error: %q is not a valid variable name\n", k)
				return 2
			}
			names = append(names, k)
		}
		sort.Strings(names)
		pairs := make([]kv, 0, len(names))
		for _, k := range names {
			pairs = append(pairs, kv{k, in[k]})
		}
		if len(pairs) == 0 {
			fmt.Fprintln(os.Stderr, "nothing to store")
			return 0
		}
		if err := NewBw().StoreFields(fs.Arg(0), pairs, *force, false); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		recordItem(fs.Arg(0))
		fmt.Fprintf(os.Stderr, "stored %d variables in %q\n", len(pairs), fs.Arg(0))
	default:
		fmt.Fprintln(os.Stderr, "usage: env-gen vault get ITEM | env-gen vault set [-force] ITEM | env-gen vault unlock")
		return 2
	}
	return 0
}
