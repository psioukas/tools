package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

var errNotFound = errors.New("item not found")

type bwItem struct {
	ID    string `json:"id,omitempty"`
	Type  int    `json:"type"`
	Name  string `json:"name"`
	Notes string `json:"notes,omitempty"`
	Login *struct {
		Username string `json:"username"`
		Password string `json:"password"`
		URIs     []struct {
			URI string `json:"uri"`
		} `json:"uris"`
	} `json:"login,omitempty"`
	Fields []bwField `json:"fields,omitempty"`
}

type bwField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Type  int    `json:"type"` // 0 text, 1 hidden
}

// Bw wraps the Bitwarden CLI (works against Vaultwarden once `bw config server` is set).
type Bw struct {
	Bin     string // BW_BIN overrides, default "bw"
	Session string // BW_SESSION
	cache   map[string]*bwItem
}

func NewBw() *Bw {
	bin := os.Getenv("BW_BIN")
	if bin == "" {
		bin = "bw"
	}
	return &Bw{Bin: bin, Session: os.Getenv("BW_SESSION"), cache: map[string]*bwItem{}}
}

func (b *Bw) run(stdin string, args ...string) ([]byte, error) {
	if b.Session != "" {
		args = append(args, "--session", b.Session)
	}
	cmd := exec.Command(b.Bin, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if strings.Contains(msg, "Not found") {
			return nil, errNotFound
		}
		return nil, fmt.Errorf("%s %s: %v: %s", b.Bin, args[0], err, msg)
	}
	return out.Bytes(), nil
}

// Ready checks the vault is unlocked.
func (b *Bw) Ready() error {
	if b.Session == "" {
		return errors.New(`vault locked: run  export BW_SESSION="$(bw unlock --raw)"`)
	}
	return nil
}

func (b *Bw) get(name string) (*bwItem, error) {
	if it, ok := b.cache[name]; ok {
		return it, nil
	}
	if err := b.Ready(); err != nil {
		return nil, err
	}
	out, err := b.run("", "get", "item", name)
	if err != nil {
		return nil, err
	}
	var it bwItem
	if err := json.Unmarshal(out, &it); err != nil {
		return nil, err
	}
	b.cache[name] = &it
	return &it, nil
}

func fieldOf(it *bwItem, field string) (string, error) {
	switch field {
	case "password", "username", "uri":
		if it.Login == nil {
			return "", fmt.Errorf("item %q has no login", it.Name)
		}
		switch field {
		case "password":
			return it.Login.Password, nil
		case "username":
			return it.Login.Username, nil
		default:
			if len(it.Login.URIs) > 0 {
				return it.Login.URIs[0].URI, nil
			}
			return "", fmt.Errorf("item %q has no uri", it.Name)
		}
	case "notes":
		return it.Notes, nil
	}
	for _, f := range it.Fields {
		if f.Name == field {
			return f.Value, nil
		}
	}
	return "", fmt.Errorf("item %q has no field %q", it.Name, field)
}

func (b *Bw) Read(item, field string) (string, error) {
	it, err := b.get(item)
	if err != nil {
		return "", err
	}
	return fieldOf(it, field)
}

type kv struct{ Key, Value string }

// Store sets one field of an item (password/username/notes are the login/notes
// fields; anything else is a hidden custom field), creating the item if needed.
func (b *Bw) Store(item, field, value string) error {
	return b.StoreFields(item, []kv{{field, value}}, true, true)
}

// StoreFields creates the item or edits it in place. The existing item is
// edited as raw JSON so attributes this tool doesn't model (folder, URIs,
// attachments, ...) are preserved. With overwrite=false, an existing field of
// the same name is an error. special=false forces every key to be a custom field.
func (b *Bw) StoreFields(item string, kvs []kv, overwrite, special bool) error {
	if err := b.Ready(); err != nil {
		return err
	}
	var raw map[string]any
	out, err := b.run("", "get", "item", item)
	exists := err == nil
	if err != nil && !errors.Is(err, errNotFound) {
		return err
	}
	if exists {
		if err := json.Unmarshal(out, &raw); err != nil {
			return err
		}
	} else {
		raw = map[string]any{"type": 1, "name": item,
			"login": map[string]any{"username": "", "password": "", "uris": []any{}}}
	}
	fields, _ := raw["fields"].([]any)
	var clash []string
	for _, p := range kvs {
		if special && (p.Key == "password" || p.Key == "username" || p.Key == "notes") {
			continue
		}
		idx := -1
		for i, f := range fields {
			if m, ok := f.(map[string]any); ok && m["name"] == p.Key {
				idx = i
			}
		}
		if idx >= 0 {
			if !overwrite {
				clash = append(clash, p.Key)
				continue
			}
			fields[idx].(map[string]any)["value"] = p.Value
		} else {
			fields = append(fields, map[string]any{"name": p.Key, "value": p.Value, "type": 1})
		}
	}
	if len(clash) > 0 {
		return fmt.Errorf("item %q already has fields %s (use -force to overwrite)", item, strings.Join(clash, ", "))
	}
	for _, p := range kvs {
		if !special {
			break
		}
		login, _ := raw["login"].(map[string]any)
		switch p.Key {
		case "password", "username":
			if login == nil {
				return fmt.Errorf("item %q has no login", item)
			}
			login[p.Key] = p.Value
		case "notes":
			raw["notes"] = p.Value
		}
	}
	raw["fields"] = fields
	js, _ := json.Marshal(raw)
	enc := base64.StdEncoding.EncodeToString(js)
	delete(b.cache, item)
	if exists {
		_, err = b.run(enc, "edit", "item", fmt.Sprint(raw["id"]))
	} else {
		_, err = b.run(enc, "create", "item")
	}
	return err
}

// Fields returns an item's custom fields in vault order.
func (b *Bw) Fields(item string) ([]bwField, error) {
	it, err := b.get(item)
	if err != nil {
		return nil, err
	}
	return it.Fields, nil
}

// Search lists vault items matching term (for the TUI picker).
func (b *Bw) Search(term string) ([]bwItem, error) {
	out, err := b.run("", "list", "items", "--search", term)
	if err != nil {
		return nil, err
	}
	var items []bwItem
	return items, json.Unmarshal(out, &items)
}
