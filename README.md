# tools

Personal automations. Each top-level directory is one self-contained tool.

```
./tools list              # show available tools
./tools <name> [args...]  # run one (or run <name>/run directly)
```

## Adding a tool

1. Create `<name>/` with an executable `run` entry point (any language; compiled tools build on demand in `run`).
2. Add a one-line `DESCRIPTION` and a `README.md`.

## Tools

| Tool | What it does |
|------|--------------|
| [env-gen](env-gen/) | Render `.env` files from templates, reading/generating secrets in Vaultwarden via `bw` |
