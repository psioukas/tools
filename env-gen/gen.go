package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// offline disables every vault operation (read, store, backup); generation stays local.
var offline bool

// noBackup hides the vault backup step in `edit` (set by -no-backup).
var noBackup bool

// generatorMode selects how {{gen}}/{{vwgen}} secrets are produced:
// "builtin" (crypto/rand) or "bw" (the Bitwarden password generator, `bw generate`,
// which runs locally and needs neither login nor network).
var generatorMode = "builtin"

// genSecret returns a random secret of n characters from the named charset.
func genSecret(n int, csName string) (string, error) {
	set, err := charsetFor(csName)
	if err != nil {
		return "", err
	}
	if generatorMode == "bw" && csName != "hex" { // bw has no hex mode; hex stays builtin
		return bwGenerate(n, csName)
	}
	return generate(n, set)
}

func bwGenerate(n int, csName string) (string, error) {
	args := []string{"generate", "--length", strconv.Itoa(n), "--lowercase", "--uppercase", "--number"}
	if csName == "symbols" {
		args = append(args, "--special")
	}
	bin := NewBw().Bin
	cmd := exec.Command(bin, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s generate: %v: %s", bin, err, strings.TrimSpace(errb.String()))
	}
	v := strings.TrimSpace(out.String())
	if len(v) != n {
		return "", fmt.Errorf("%s generate returned %d characters, wanted %d (bw allows lengths 5-128)", bin, len(v), n)
	}
	return v, nil
}
