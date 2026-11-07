package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// The cache remembers vault item and field NAMES you used before, so the TUI can
// offer them as quick picks. It never stores secret values, passwords or sessions.
//
//	Linux/macOS: $XDG_CACHE_HOME/env-gen/recent.json (default ~/.cache/env-gen/recent.json)
//	Override with ENV_GEN_CACHE=/path/to/file
type recentItem struct {
	Name   string    `json:"name"`
	Fields []string  `json:"fields,omitempty"`
	Used   time.Time `json:"used"`
}

const maxRecent = 30

func cachePath() string {
	if p := os.Getenv("ENV_GEN_CACHE"); p != "" {
		return p
	}
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "env-gen", "recent.json")
}

func loadRecent() []recentItem {
	p := cachePath()
	if p == "" || cfg.Get("defaults.cache", "on") == "off" {
		return nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var items []recentItem
	if json.Unmarshal(b, &items) != nil {
		return nil
	}
	return items
}

// recordItem notes that an item (and fields of it) was used. Failures are ignored:
// the cache is a convenience, never a requirement.
func recordItem(name string, fields ...string) {
	p := cachePath()
	if p == "" || name == "" || cfg.Get("defaults.cache", "on") == "off" {
		return
	}
	items := loadRecent()
	idx := -1
	for i := range items {
		if items[i].Name == name {
			idx = i
		}
	}
	if idx < 0 {
		items = append(items, recentItem{Name: name})
		idx = len(items) - 1
	}
	items[idx].Used = time.Now().UTC()
	for _, f := range fields {
		if f == "" || containsStr(items[idx].Fields, f) {
			continue
		}
		items[idx].Fields = append(items[idx].Fields, f)
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].Used.After(items[j].Used) })
	if len(items) > maxRecent {
		items = items[:maxRecent]
	}
	if os.MkdirAll(filepath.Dir(p), 0o700) != nil {
		return
	}
	if b, err := json.MarshalIndent(items, "", "  "); err == nil {
		_ = os.WriteFile(p, b, 0o600)
	}
}

func containsStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// runCache implements: env-gen cache [list|clear|path]
func runCache(args []string) int {
	cmd := "list"
	if len(args) > 0 {
		cmd = args[0]
	}
	switch cmd {
	case "path":
		fmt.Println(cachePath())
	case "list":
		if exp, ok := sessionExpiry(); ok {
			fmt.Printf("session: cached, expires %s (key not shown)\n", exp.Local().Format("15:04:05"))
		} else {
			fmt.Println("session: not cached")
		}
		items := loadRecent()
		if len(items) == 0 {
			fmt.Fprintln(os.Stderr, "no cached vault items")
		}
		for _, it := range items {
			fmt.Printf("%-30s %v\n", it.Name, it.Fields)
		}
	case "clear":
		if p := cachePath(); p != "" {
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				fmt.Fprintln(os.Stderr, "error:", err)
				return 1
			}
		}
		fmt.Fprintln(os.Stderr, "cache cleared")
	default:
		fmt.Fprintln(os.Stderr, "usage: env-gen cache [list | clear | path]")
		return 2
	}
	return 0
}
