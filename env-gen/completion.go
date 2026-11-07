package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// runComplete serves dynamic candidates to the shell scripts. It only reads local
// caches and config; it never calls the vault.
//
//	env-gen __complete items            recently used vault item names
//	env-gen __complete fields ITEM      field names seen for ITEM
//	env-gen __complete config-keys      known config keys
func runComplete(args []string) int {
	if len(args) == 0 {
		return 0
	}
	switch args[0] {
	case "items":
		for _, r := range loadRecent() {
			fmt.Println(r.Name)
		}
	case "fields":
		if len(args) > 1 {
			for _, r := range loadRecent() {
				if r.Name == args[1] {
					for _, f := range r.Fields {
						fmt.Println(f)
					}
				}
			}
		}
	case "config-keys":
		for _, e := range configKeys {
			fmt.Println(e.Key)
		}
	}
	return 0
}

func runCompletion(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, `usage: env-gen completion bash|zsh|fish|install

  source <(env-gen completion bash)                   # try it in this shell
  env-gen completion install                          # bash/fish: drops a file in your user completion dir
  source <(env-gen completion zsh)                    # zsh: add this line to ~/.zshrc
  env-gen completion fish > ~/.config/fish/completions/env-gen.fish
`)
		return 2
	}
	switch args[0] {
	case "bash":
		fmt.Print(bashCompletion)
	case "zsh":
		fmt.Print(zshCompletion)
	case "fish":
		fmt.Print(fishCompletion)
	case "install":
		return installCompletion()
	default:
		fmt.Fprintf(os.Stderr, "unknown shell %q (bash|zsh|fish|install)\n", args[0])
		return 2
	}
	return 0
}

func installCompletion() int {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	var path, script string
	switch filepath.Base(os.Getenv("SHELL")) {
	case "bash":
		data := os.Getenv("XDG_DATA_HOME")
		if data == "" {
			data = filepath.Join(home, ".local", "share")
		}
		path, script = filepath.Join(data, "bash-completion", "completions", "env-gen"), bashCompletion
	case "fish":
		cfgDir := os.Getenv("XDG_CONFIG_HOME")
		if cfgDir == "" {
			cfgDir = filepath.Join(home, ".config")
		}
		path, script = filepath.Join(cfgDir, "fish", "completions", "env-gen.fish"), fishCompletion
	case "zsh":
		fmt.Fprintln(os.Stderr, "zsh: add this line to ~/.zshrc (I don't edit rc files for you):\n\n  source <(env-gen completion zsh)")
		return 0
	default:
		fmt.Fprintf(os.Stderr, "can't tell your shell from $SHELL=%q; use: env-gen completion bash|zsh|fish\n", os.Getenv("SHELL"))
		return 1
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if err := os.WriteFile(path, []byte(script), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "installed %s\nOpen a new shell (bash needs the bash-completion package for auto-loading).\n", path)
	return 0
}

const bashCompletion = `# bash completion for env-gen   (source <(env-gen completion bash))
_env_gen() {
  local cur="${COMP_WORDS[COMP_CWORD]}" sub="${COMP_WORDS[1]}" sub2="${COMP_WORDS[2]}"
  local cmds="new edit push pull setup unlock lock keys cache config completion"
  COMPREPLY=()
  if [[ $COMP_CWORD -eq 1 ]]; then
    COMPREPLY=($(compgen -W "$cmds -h -force -dry-run -o -set -backup -offline -generator" -- "$cur"))
    [[ -z "$cur" || "$cur" != -* ]] && COMPREPLY+=($(compgen -f -- "$cur"))
    return
  fi
  if [[ "$cur" == -* ]]; then
    local flags=""
    case "$sub" in
      new)   flags="-o -force -dry-run -from -blank -offline -generator" ;;
      edit)  flags="-set -unset -backup -dry-run -offline -generator" ;;
      push)  flags="-item -force -dry-run -no-template" ;;
      pull)  flags="-o -force -dry-run" ;;
      keys)  flags="-y -length -charset" ;;
      *)     flags="-force -dry-run -o -set -backup -offline -generator" ;;
    esac
    COMPREPLY=($(compgen -W "$flags" -- "$cur"))
    return
  fi
  case "$sub" in
    completion) [[ $COMP_CWORD -eq 2 ]] && COMPREPLY=($(compgen -W "bash zsh fish install" -- "$cur")) ;;
    cache)      [[ $COMP_CWORD -eq 2 ]] && COMPREPLY=($(compgen -W "list clear path" -- "$cur")) ;;
    config)
      if [[ $COMP_CWORD -eq 2 ]]; then
        COMPREPLY=($(compgen -W "list path get set unset" -- "$cur"))
      elif [[ $COMP_CWORD -eq 3 && "$sub2" =~ ^(get|set|unset)$ ]]; then
        COMPREPLY=($(compgen -W "$(env-gen __complete config-keys 2>/dev/null)" -- "$cur"))
      fi ;;
    keys)
      if [[ $COMP_CWORD -eq 2 ]]; then
        COMPREPLY=($(compgen -W "list show rm rename rotate recent" -- "$cur"))
      elif [[ $COMP_CWORD -eq 3 ]]; then
        COMPREPLY=($(compgen -W "$(env-gen __complete items 2>/dev/null)" -- "$cur"))
      elif [[ $COMP_CWORD -ge 4 ]]; then
        local item="${COMP_WORDS[3]}"
        [[ "$item" == -* ]] && item="${COMP_WORDS[4]}"
        COMPREPLY=($(compgen -W "$(env-gen __complete fields "$item" 2>/dev/null)" -- "$cur"))
      fi ;;
    pull) [[ $COMP_CWORD -ge 2 ]] && COMPREPLY=($(compgen -W "$(env-gen __complete items 2>/dev/null)" -- "$cur")) ;;
    *)    COMPREPLY=($(compgen -f -- "$cur")) ;;
  esac
}
complete -o default -F _env_gen env-gen
`

const zshCompletion = `# zsh completion for env-gen   (source <(env-gen completion zsh))
autoload -U +X compinit && compinit 2>/dev/null
autoload -U +X bashcompinit && bashcompinit
` + bashCompletion

const fishCompletion = `# fish completion for env-gen
set -l cmds new edit push pull setup unlock lock keys cache config completion
complete -c env-gen -f
complete -c env-gen -n "not __fish_seen_subcommand_from $cmds" -a "$cmds"
complete -c env-gen -n "not __fish_seen_subcommand_from $cmds" -F
complete -c env-gen -n "__fish_seen_subcommand_from keys; and not __fish_seen_subcommand_from list show rm rename rotate recent" -a "list show rm rename rotate recent"
complete -c env-gen -n "__fish_seen_subcommand_from keys; and __fish_seen_subcommand_from list show rm rename rotate" -a "(env-gen __complete items 2>/dev/null)"
complete -c env-gen -n "__fish_seen_subcommand_from pull" -a "(env-gen __complete items 2>/dev/null)"
complete -c env-gen -n "__fish_seen_subcommand_from cache; and not __fish_seen_subcommand_from list clear path" -a "list clear path"
complete -c env-gen -n "__fish_seen_subcommand_from config; and not __fish_seen_subcommand_from list path get set unset" -a "list path get set unset"
complete -c env-gen -n "__fish_seen_subcommand_from config; and __fish_seen_subcommand_from get set unset" -a "(env-gen __complete config-keys 2>/dev/null)"
complete -c env-gen -n "__fish_seen_subcommand_from completion" -a "bash zsh fish install"
complete -c env-gen -s o -r -d "output file"
complete -c env-gen -l force -d "overwrite existing files"
complete -c env-gen -o force -d "overwrite existing files"
complete -c env-gen -o dry-run -d "show, don't write"
complete -c env-gen -o offline -d "no vault; secrets via bw generate"
complete -c env-gen -o backup -r -d "also store variables in this vault item"
complete -c env-gen -o set -r -d "KEY=VALUE"
complete -c env-gen -o unset -r -d "KEY to remove (edit)"
complete -c env-gen -o from -r -d "example file for new"
complete -c env-gen -o blank -d "ignore example file"
complete -c env-gen -o generator -r -a "builtin bw"
complete -c env-gen -o item -r -d "vault item for push"
`
