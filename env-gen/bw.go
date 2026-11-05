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

// Store creates the item (or adds the field to it) holding value.
func (b *Bw) Store(item, field, value string) error {
	it, err := b.get(item)
	if errors.Is(err, errNotFound) {
		it = &bwItem{Type: 1, Name: item}
		it.Login = &struct {
			Username string `json:"username"`
			Password string `json:"password"`
			URIs     []struct {
				URI string `json:"uri"`
			} `json:"uris"`
		}{}
		setField(it, field, value)
		return b.create(it)
	}
	if err != nil {
		return err
	}
	setField(it, field, value)
	js, _ := json.Marshal(it)
	_, err = b.run(base64.StdEncoding.EncodeToString(js), "edit", "item", it.ID)
	return err
}

func setField(it *bwItem, field, value string) {
	switch field {
	case "password":
		if it.Login != nil {
			it.Login.Password = value
		}
	case "notes":
		it.Notes = value
	default:
		it.Fields = append(it.Fields, bwField{Name: field, Value: value, Type: 1})
	}
}

func (b *Bw) create(it *bwItem) error {
	js, _ := json.Marshal(it)
	out, err := b.run(base64.StdEncoding.EncodeToString(js), "create", "item")
	if err != nil {
		return err
	}
	var created bwItem
	if json.Unmarshal(out, &created) == nil {
		b.cache[it.Name] = &created
	}
	return nil
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
