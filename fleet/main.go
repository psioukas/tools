// fleet manages the environment variables and secrets of your apps across machines.
// apps.yaml (names only) says which app runs where; Vaultwarden, through env-gen,
// holds the values; drivers (file, ssh, docker) read and write the targets.
package main

import (
	"fmt"
	"os"
	"os/exec"
)

func execCommand(name string, args ...string) *exec.Cmd {
	c := exec.Command(name, args...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	return c
}

const usage = `fleet: variables and secrets for apps on VMs, Docker and local files

usage:
  fleet init [FILE]                    write a sample apps.yaml
  fleet apps                           list apps, targets and where their files live
  fleet status [-check] [-j N] [APP...] in sync or drifted, per target (N targets in parallel, default 4)
  fleet diff [-values] APP [TARGET]    which variables differ (names only by default)
  fleet push [-y] [-dry-run] [-prune] [-reload] APP [TARGET]
                                       write vault values (plus overrides) to targets
  fleet pull [-y] [-dry-run] APP TARGET
                                       import a target's variables into the vault
  fleet edit [-push] APP [TARGET]      edit the vault item with the arrow-key editor, then push
  fleet ui init | ui admin-init | ui -host H -trust-proxy
                                       web UI behind your HTTPS reverse proxy (see README)

All commands take -f apps.yaml (default: ./apps.yaml, $FLEET_CONFIG, ~/.config/fleet/apps.yaml).
Vault access goes through env-gen (FLEET_ENVGEN overrides its path); ssh through FLEET_SSH.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	args := os.Args[2:]
	var code int
	switch os.Args[1] {
	case "init":
		code = cmdInit(args)
	case "apps", "list":
		code = cmdApps(args)
	case "status":
		code = cmdStatus(args)
	case "diff":
		code = cmdDiff(args)
	case "push":
		code = cmdPush(args)
	case "pull":
		code = cmdPull(args)
	case "edit":
		code = cmdEdit(args)
	case "ui":
		code = runUI(args)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		code = 2
	}
	os.Exit(code)
}
