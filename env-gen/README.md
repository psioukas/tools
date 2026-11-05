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

## Placeholders

| Placeholder | Meaning |
|---|---|
| `{{gen:N[:alnum\|hex\|symbols]}}` | random value of length N |
| `{{prompt:Label}}` | ask interactively (input is echoed) |
| `{{vw:Item/field}}` | read from Vaultwarden; field = `password` (default), `username`, `uri`, `notes`, or a custom field |
| `{{vwgen:Item/field:N[:charset]}}` | read from Vaultwarden, or generate and store it there if missing, so re-runs are stable |

Existing outputs are skipped unless `-force`. `-dry-run` prints to stdout and never writes to the vault.

Test with a fake vault via `BW_BIN=/path/to/fake-bw`. Unit tests: `go test ./...`.
