# env-gen

Renders `*.env.template` files into sibling `.env` files (mode 0600), batching over any number of files/directories.

```
export BW_SESSION="$(bw unlock --raw)"   # bw must point at your Vaultwarden server
./tools env-gen ~/projects               # all templates found recursively
./tools env-gen -dry-run app/.env.template
./tools env-gen -force app/
```

## Without a template

```
# inline: same placeholders, values auto-quoted when needed
./tools env-gen -o app/.env -set 'DB_PASS={{vwgen:myapp db/password:24}}' -set 'NAME=hello world'

# interactive TUI: pick a source per variable (literal, hidden secret, generate,
# vault read, vault read-or-generate-and-store, with a vault item search picker),
# review the plan, optionally save it as a reusable .env.template
./tools env-gen new -o app/.env
```

Secrets typed into the TUI are never written to a saved template (a `{{prompt:KEY}}` is saved instead).

## Guided setup

```
eval "$(./env-gen setup)"
```
Checks that `bw` is installed, asks for your Vaultwarden URL (runs `bw config server`; offers to log out if you're changing server), runs `bw login` if needed (email, password and 2FA are handled by `bw` itself), unlocks with a hidden master-password prompt (passed to `bw` via an environment variable, not the command line), syncs, and confirms the connection. All messages go to stderr; stdout carries only `export BW_SESSION=...`, so wrapping it in `eval` leaves the session in your shell. Without `eval` you still get the setup, but the session is not kept.

## Config file

`setup` saves your settings to a file in your user config directory, like `~/.aws/config` or git's config:

| OS | Path |
|---|---|
| Linux / macOS | `$XDG_CONFIG_HOME/env-gen/config` (default `~/.config/env-gen/config`) |
| Windows | `%AppData%\env-gen\config` |

Override with `ENV_GEN_CONFIG=/path/to/file`. The directory is created `0700` and the file `0600`. It holds settings only, never the master password or `BW_SESSION`.

```
[vault]
server = https://vault.example.com
email = me@example.com
bw = /usr/local/bin/bw
[defaults]
output = .env
length = 32
charset = alnum
```

```
env-gen config list | path | get KEY | set KEY VALUE | unset KEY
```

Precedence: command-line flags, then `BW_BIN`, then the config file, then built-in defaults. Everything (render, `-set`, `new`, `push`, `pull`, `setup`, `config`) is one binary; the only external dependency is the Bitwarden CLI.

## Moving existing .env files in and out of the vault

```
./tools env-gen push -item myapp app/.env   # each variable -> hidden custom field of vault item "myapp";
                                            # writes app/.env.template with {{vw:myapp/KEY}} lines
./tools env-gen pull -o app/.env myapp      # rebuild a .env straight from a vault item
```

`push` refuses to overwrite fields that already exist unless `-force`, and edits existing items in place so other item data (folder, URIs, attachments) is kept. Item defaults to the project directory name. The plaintext `.env` is left alone; delete it yourself once you've checked with `pull`.

## Placeholders

| Placeholder | Meaning |
|---|---|
| `{{gen:N[:alnum\|hex\|symbols]}}` | random value of length N |
| `{{prompt:Label}}` | ask interactively (input is echoed) |
| `{{vw:Item/field}}` | read from Vaultwarden; field = `password` (default), `username`, `uri`, `notes`, or a custom field |
| `{{vwgen:Item/field:N[:charset]}}` | read from Vaultwarden, or generate and store it there if missing, so re-runs are stable |

Existing outputs are skipped unless `-force`. `-dry-run` prints to stdout and never writes to the vault.

Test with a fake vault via `BW_BIN=/path/to/fake-bw`. Unit tests: `go test ./...`.

## Standalone binary (Linux VM)

`./build.sh` (needs only Go) writes static `dist/env-gen-linux-{amd64,arm64}` binaries; CI also uploads them as a workflow artifact. Copy one to the VM and run it, no runtime or Go needed there.

The VM does need the Bitwarden CLI (`bw`), which is a single downloadable binary from bitwarden.com/download. Then:

```
bw config server https://vault.example.com
bw login
export BW_SESSION="$(bw unlock --raw)"
./env-gen new
```
