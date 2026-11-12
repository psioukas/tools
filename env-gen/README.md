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

**From an example file.** Run `env-gen new` in a project directory that has a `.env.example` (also `.env.sample`, `.env.dist`, `example.env`) and it uses that as the starting point: variables whose names look secret (`PASSWORD`, `SECRET`, `TOKEN`, `API_KEY`, `JWT`, ...) are suggested as "generate and store in vault item `<project folder>`", everything else keeps the example value. Accept the suggestions in one step, or customize each variable (keep, skip, literal, hidden secret, generate, vault read, vault read-or-generate). Then review the plan, optionally save it as `.env.template`, and write `.env`. Use `-from FILE` to pick a different example, or `-blank` to ignore it.

**Vault backup.** `new` asks for a "Back up ALL variables to this vault item" (default: the project folder name). Every variable written to `.env`, including kept example values and typed literals, is also stored as a hidden custom field of that item, and existing fields are updated to match. The backup happens before `.env` is written, so if it fails (vault locked, network), no `.env` is written. Clear the field to skip. In template and `-set` modes, add `-backup ITEM` to get the same behaviour. `-dry-run` never touches the vault. `env-gen pull ITEM` rebuilds the `.env` from the backup.

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

## Editing an existing .env

```
env-gen edit                  # in a directory with .env files: pick the file, then edit interactively
env-gen edit .env.production  # skip the file prompt
env-gen edit -set PORT=4000 -set 'TOKEN={{vwgen:myapp/TOKEN:32}}' -unset OLD_VAR -backup myapp   # no prompts (defaults to ./.env)
```

The interactive flow:
1. **Pick a file.** With several `.env`-style files in the directory (`.env`, `.env.production`, `app.env`, ...) you are asked which one; with a single one it opens directly.
2. **Browse the variables** with the arrow keys (`/` filters). Each entry is shown as `KEY="value"`, tagged `(modified)` or `(new)` when changed in this session. Secret-looking values (`PASSWORD`, `TOKEN`, `SECRET`, ...) are masked as `••••••••`; choose "Show secret values" in the list to reveal them.
3. **Select a variable** and choose: edit it inline (the current value is prefilled, change it in place), enter a new value (hidden while typing for secret-looking names), generate or take it from the vault, rename it, or delete it (with a confirmation).
4. **Done** shows a `+ ~ -` summary of changed variable names, then asks to save. The previous file is kept as `FILE.bak` (0600), and the save offers the same "back up ALL variables to a vault item" step as `new`.

Comments, blank lines, ordering, `export` prefixes and inline `# comments` on a changed line are preserved. In scripted mode the backup only happens with `-backup ITEM`, and `-dry-run` prints the result instead of writing.

## Web UI (behind your HTTPS reverse proxy)

`env-gen ui` serves an editor you can open from any browser, such as an Android tablet: browse projects, open a `.env` or `.env.example`, change / rename / delete / add variables, pick a source per variable (typed, generated, vault read, vault read-or-generate), preview the diff, save, create `.env` from an example, and back up everything to a vault item. Secret-looking values are never sent to the browser until you press Reveal. The pages are embedded in the binary.

```
env-gen ui init      # once: creates the editor 2FA (TOTP) secret; add the key to an authenticator app
env-gen ui admin-init   # once, optional: admin passphrase + separate admin authenticator key (see below)
env-gen ui -root ~/projects -host vault.example.com -trust-proxy      # listens on 127.0.0.1:8765
```

Reverse proxy examples (TLS terminates there; the UI refuses anything that isn't https via the proxy):

```
# Caddy
vault.example.com {
    reverse_proxy 127.0.0.1:8765
}

# nginx (inside your TLS server block)
location / {
    proxy_pass http://127.0.0.1:8765;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $remote_addr;   # overwrite, don't append client-supplied values
}
```

Run it under systemd or tmux. For development without a proxy: `env-gen ui -insecure-http` (loopback only).

**Security model.** This puts a path to your vault on a public URL, so it is locked down accordingly; still, treat it as sensitive and consider also restricting it by IP or VPN at the proxy.
- **Login = master password + authenticator code.** The code is checked first, and each code can be used only once. Failed logins are rate-limited (5 per IP, 20 overall, then lockouts of 10 minutes doubling up to 24h).
- **One session at a time**, held in server memory only. The vault session key never reaches the browser and is never written to disk by the UI; idle timeout 15 minutes (`-idle`), 8 hours maximum. The cookie is `__Host-` prefixed, `Secure`, `HttpOnly`, `SameSite=Strict`, and state-changing requests also need a per-session CSRF token and a same-origin check.
- **Strict CSP**, no inline scripts, `no-store` caching, HSTS, and allowed `-host` names only (blocks DNS rebinding).
- **File access is sandboxed** to `-root`: only `.env`-style names, no `..`, no symlink escapes, files written 0600 with the previous version kept as `.bak`.
- The server needs the Bitwarden CLI logged in (`env-gen setup` on the VM first). The UI ignores the on-disk session cache and `BW_SESSION`: only a UI login can open the vault there.
- Not built into the UI (use the CLI): offline mode and setup.

**Admin sign-in (keys, push, pull, vault storing).** Everything that creates or changes things in the vault needs a second, separate credential, so the editor login alone can't do it:

```
env-gen ui admin-init     # sets an admin passphrase (12+ chars) and prints a SEPARATE authenticator key
```

| Needs only the editor login | Needs admin sign-in (5 minutes, `-admin-ttl`) |
|---|---|
| browse and edit `.env` files, typed or generated values, vault reads (`vw`), search | vault key list / reveal / generate / rotate / rename / delete |
| preview, save, create from `.env.example` | push a `.env` into the vault, pull a vault item into a `.env` |
| | storing values in the vault from the editor: backup item, "generate + store" (`vwgen`) |

The admin passphrase is stored only as a PBKDF2-SHA256 hash in `ui.json` (0600), the admin authenticator secret is different from the editor one, its failures have their own rate limit and lockout, and elevation is per session and can be dropped at any time. Every admin action is written to the server log (`audit ...` lines: action, client IP, item and field names, never values). If `admin-init` hasn't been run, the admin features stay disabled. The UI never returns a generated secret in the response; use Reveal to read it.

## Shell auto-completion

```
env-gen completion install                 # bash/fish: writes a file in your user completion dir
source <(env-gen completion bash)          # or just try it in this shell
source <(env-gen completion zsh)           # zsh: add this line to ~/.zshrc
env-gen completion fish > ~/.config/fish/completions/env-gen.fish
```

Completes subcommands, flags per command, `keys`/`cache`/`config` subcommands, config key names, and vault item and field names from the local recent-items cache (so it is instant and never calls the vault; an item shows up after you've used it once). Without the `bash-completion` package, use the `source` line.

## Unlock session

```
env-gen unlock     # hidden master-password prompt; session cached for 1h
env-gen lock       # clear the cached session (and run bw lock)
```

The unlock session (`BW_SESSION`) is cached in `~/.cache/env-gen/session` (override `ENV_GEN_SESSION`) with mode 0600 and an expiry, and every command picks it up when `BW_SESSION` isn't exported. In a terminal, a command that needs the vault and finds none just prompts to unlock. A cached key is a bearer key to your vault until it expires, so keep the TTL short: `env-gen config set session.ttl 15m`, or turn it off with `env-gen config set session.cache off`. A cache file readable by others is ignored. `env-gen cache list` shows whether a session is cached (never the key).

## Managing stored keys

```
env-gen keys list [ITEM]                # fields in a vault item (default: this folder's name), values hidden
env-gen keys show ITEM KEY              # print one value
env-gen keys rename ITEM OLD NEW
env-gen keys rotate [-y] [-length 40] [-charset symbols] ITEM KEY   # fresh random value
env-gen keys rm [-y] ITEM KEY...
```

Edits keep the rest of the vault item intact. Rotating or removing a value doesn't change `.env` files already written: re-run `env-gen pull ITEM` or `env-gen edit`. Destructive commands ask for confirmation, or need `-y` when there's no terminal.

## Recent vault items

Vault item and field names you use (in the TUI pickers, placeholders, backups) are remembered in `~/.config`-style cache `$XDG_CACHE_HOME/env-gen/recent.json` (default `~/.cache/env-gen/recent.json`, override `ENV_GEN_CACHE`), up to 30 entries. The pickers list them first, before "search the vault" or "type a name". It stores names only: never values, passwords or session keys. `env-gen cache list | clear | path`; turn off with `env-gen config set defaults.cache off`.

## Offline / one-time mode

```
env-gen new -offline          # TUI, example-file aware, no vault anywhere
env-gen -offline -o .env -set 'JWT={{gen:48}}' -set 'DB={{vwgen:app/db:24:symbols}}'
```

`-offline` never talks to Vaultwarden: no login, no `BW_SESSION`, no backup prompt, nothing is stored. Secrets are made with the Bitwarden password generator (`bw generate`, which runs locally and needs no login or network). `{{vwgen:...}}` becomes a plain one-time generate, `{{vw:...}}` is an error, and `-backup` is refused. Because nothing is stored, the output file is the only copy of those values.

Hex secrets always use the built-in generator (`bw generate` has no hex mode). To use `bw generate` online too, pass `-generator bw` or `env-gen config set defaults.generator bw`. Lengths must be 5-128 in that mode.

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
