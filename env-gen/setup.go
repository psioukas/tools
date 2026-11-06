package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/huh"
)

type bwStatus struct {
	ServerURL string `json:"serverUrl"`
	UserEmail string `json:"userEmail"`
	Status    string `json:"status"` // unauthenticated | locked | unlocked
}

func status(bw *Bw) (bwStatus, error) {
	var st bwStatus
	out, err := bw.run("", "status")
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(out, &st)
}

func say(format string, a ...any) { fmt.Fprintf(os.Stderr, format+"\n", a...) }

// runSetup walks through server URL, login, unlock and a connection test.
// All prose goes to stderr; stdout carries only the `export BW_SESSION=...`
// line, so  eval "$(env-gen setup)"  puts the session in your shell.
func runSetup() int {
	bw := NewBw()
	if _, err := exec.LookPath(bw.Bin); err != nil {
		say("The Bitwarden CLI (%q) was not found in PATH.\nDownload the single binary from https://bitwarden.com/download (CLI), unzip it,\nand put it somewhere on PATH (for example /usr/local/bin/bw), then re-run setup.", bw.Bin)
		return 1
	}
	st, err := status(bw)
	if err != nil {
		say("error: %v", err)
		return 1
	}

	// 1. server URL
	say("bw status: %s (server: %s)", st.Status, orNone(st.ServerURL))
	server := cfg.Get("vault.server", st.ServerURL)
	if server == "https://bitwarden.com" || server == "https://vault.bitwarden.com" {
		server = ""
	}
	if err := newForm(huh.NewGroup(huh.NewInput().
		Title("Vaultwarden server URL").Description("e.g. https://vault.example.com").Value(&server).
		Validate(func(s string) error {
			u, err := url.Parse(strings.TrimSpace(s))
			if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
				return errors.New("enter a full http(s) URL")
			}
			return nil
		}))).Run(); err != nil {
		return abort(err)
	}
	server = strings.TrimRight(strings.TrimSpace(server), "/")
	if strings.HasPrefix(server, "http://") {
		say("warning: plain http sends your master password unencrypted; prefer https.")
	}
	if server != strings.TrimRight(st.ServerURL, "/") {
		if st.Status != "unauthenticated" {
			var ok bool
			if err := newForm(huh.NewGroup(huh.NewConfirm().
				Title("Changing the server requires logging out of " + orNone(st.UserEmail) + ". Log out now?").Value(&ok))).Run(); err != nil {
				return abort(err)
			}
			if !ok {
				say("cancelled")
				return 1
			}
			if _, err := bw.run("", "logout"); err != nil {
				say("error: %v", err)
				return 1
			}
		}
		saved := bw.Session
		bw.Session = "" // config doesn't take a session
		_, err := bw.run("", "config", "server", server)
		bw.Session = saved
		if err != nil {
			say("error: %v", err)
			return 1
		}
		say("server set to %s", server)
	}

	// 2. login (interactive: handles email, password and 2FA itself)
	if st, err = status(bw); err != nil {
		say("error: %v", err)
		return 1
	}
	if st.Status == "unauthenticated" {
		say("Logging in; bw will ask for your email, master password and 2FA code.")
		cmd := exec.Command(bw.Bin, "login")
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr
		if err := cmd.Run(); err != nil {
			say("login failed: %v", err)
			return 1
		}
		if st, err = status(bw); err != nil {
			say("error: %v", err)
			return 1
		}
	}

	// 3. unlock, unless the current BW_SESSION already works
	if st.Status != "unlocked" || bw.Session == "" {
		var pw string
		if err := newForm(huh.NewGroup(huh.NewInput().Title("Master password").
			EchoMode(huh.EchoModePassword).Value(&pw))).Run(); err != nil {
			return abort(err)
		}
		cmd := exec.Command(bw.Bin, "unlock", "--raw", "--passwordenv", "ENVGEN_BW_PW")
		cmd.Env = append(os.Environ(), "ENVGEN_BW_PW="+pw) // not on the command line, so not visible in ps
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		if err := cmd.Run(); err != nil {
			say("unlock failed: %s", strings.TrimSpace(errb.String()))
			return 1
		}
		bw.Session = strings.TrimSpace(out.String())
	}

	// 4. connection test
	if _, err := bw.run("", "sync"); err != nil {
		say("sync failed: %v", err)
		return 1
	}
	out, err := bw.run("", "list", "folders")
	if err != nil {
		say("test failed: %v", err)
		return 1
	}
	var folders []json.RawMessage
	_ = json.Unmarshal(out, &folders)
	say("OK: connected to %s as %s (%d folders visible)", server, orNone(st.UserEmail), len(folders))

	// 5. remember the settings (never the session or password)
	cfg.Set("vault.server", server)
	if st.UserEmail != "" {
		cfg.Set("vault.email", st.UserEmail)
	}
	if p, err := exec.LookPath(bw.Bin); err == nil {
		if abs, err := filepath.Abs(p); err == nil {
			cfg.Set("vault.bw", abs)
		}
	}
	if err := cfg.Save(); err != nil {
		say("warning: could not save config: %v", err)
	} else {
		say("settings saved to %s", cfg.Path)
	}

	// 6. hand the session to the shell
	fmt.Printf("export BW_SESSION='%s'\n", bw.Session)
	if fi, err := os.Stdout.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		say("\nTo keep this session in your shell, run:  eval \"$(env-gen setup)\"")
	}
	return 0
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
