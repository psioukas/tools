# fleet

Manage the environment variables and secrets of your apps across VMs, Docker and local files.

- **`apps.yaml`** (in git, names only) says which app runs where and which vault item feeds each target.
- **Vaultwarden** holds the values. All vault access goes through [`env-gen`](../env-gen/) (`env-gen vault get|set`), so there is one implementation of unlocking, sessions and field handling.
- **Drivers** read and write the targets: `file` (local), `ssh` (any machine you can ssh to) and `docker` (an env file plus the container or compose service that uses it, local or over ssh).

```
fleet init                          # write a sample apps.yaml
fleet apps                          # apps, targets, where their files live
fleet status [-check] [APP...]      # in sync or drifted, per target (-check: exit 1 for cron/CI)
fleet diff [-values] APP [TARGET]   # which variables differ; names only unless -values
fleet push [-y] [-dry-run] [-prune] [-reload] APP [TARGET]
fleet pull [-y] [-dry-run] APP TARGET
fleet edit [-push] APP [TARGET]     # arrow-key editor (env-gen edit) on the vault item, then push
```

## apps.yaml

```yaml
apps:
  shop:
    vault_item: shop            # default item holding this app's variables
    exclude: [LOCAL_ONLY]       # keys never sent anywhere
    targets:
      prod-vm:
        driver: ssh
        host: deploy@10.0.0.12  # anything ssh accepts, incl. ~/.ssh/config aliases
        file: /srv/shop/.env
        vault_item: shop-prod   # this target takes its values from another item
        overrides: { APP_ENV: production }   # literal, non-secret, per target
        reload: docker compose --project-directory /srv/shop up -d --force-recreate
      staging:
        driver: docker
        host: staging           # docker files and commands run on this host over ssh
        file: /srv/shop/.env
        container: shop-web     # lets `status` notice a container running stale values
        compose_dir: /srv/shop
        service: web            # default reload: compose up -d --force-recreate web
      laptop:
        driver: file
        file: ~/projects/shop/.env
```

| Field | Meaning |
|---|---|
| `vault_item` (app) | default vault item; defaults to the app name |
| `exclude` (app, target) | keys never sent |
| `include` (target) | if set, only these keys are sent |
| `vault_item` (target) | take values from another item (staging vs prod) |
| `overrides` (target) | literal values that win over the vault; never imported by `pull` |
| `driver` | `file`, `ssh` or `docker` |
| `file` | env file path; `~/` is expanded (locally, or on the remote host) |
| `host`, `port`, `identity` | ssh destination, port, key; your `~/.ssh/config` applies too |
| `reload` | command run after a push when you pass `-reload` |
| docker: `container`, `context`, `compose_dir`, `service` | see below |

Unknown fields are rejected, so typos don't silently do nothing. The file is looked up as `-f PATH`, `$FLEET_CONFIG`, `./apps.yaml`, then `~/.config/fleet/apps.yaml`.

## How a push works

For each target, the wanted variables are: the vault item's values, minus excluded keys, limited to `include`, with `overrides` on top. They are compared with the file on the target:

- `+` missing on the target, `~` different, `-` only on the target.
- `push` writes `+` and `~` entries into the existing file, keeping comments, order and unrelated variables. `-` entries are kept unless you pass `-prune`.
- You see the plan for every selected target and confirm once (`-y` skips, `-dry-run` stops after the plan).
- The previous file is kept as `FILE.bak` on the target. New files are created `0600`; an existing file keeps its mode (locally always; over ssh when the remote has GNU `chmod --reference`).
- **Reload is opt-in**: without `-reload`, fleet writes the file and tells you the target was not reloaded. With `-reload` it runs the target's `reload` command (for `docker` targets with `service` or `container` there is a sensible default; see below).

Values are never printed unless you ask (`diff -values`). `status` and `diff` show key names only.

## Pull and edit

- `fleet pull APP TARGET` imports a target's variables into the vault item that feeds it (creating the item if needed), skipping excluded keys and overrides. You see the key names first and confirm.
- `fleet edit APP [TARGET]` opens `env-gen edit` on a private temporary copy of the vault item, stores your changes (and removals) back in the vault, removes the temp copy, then offers to push. `-push` pushes straight away. With a target, the target's item is edited; without, the app's item.

## Docker targets

The env file is the source of what containers read at start. A `docker` target manages that file (locally, or on `host` over ssh) and knows how to apply it:

- `service` + `compose_dir`: default reload is `docker compose --project-directory DIR up -d --force-recreate SERVICE`. (A plain restart would keep the old `env_file` values; recreate re-reads them.)
- `container` only: default reload is `docker restart CONTAINER`. This does **not** re-read an `env_file`, so prefer compose, or set your own `reload`.
- `container` also lets `status` compare the running container's environment (`docker inspect`) with what should be there and flag "running container differs", which catches a push that was never reloaded.
- `context` selects a docker context for local commands. When `host` is set, commands run on the host over ssh and `context` is not used.

## Adding a driver

A driver is one small interface in `driver.go`: `Describe`, `Read`, `Write` and `Reload` (plus the optional `RuntimeChecker`). Implement it, add it to `registry`, and allow its name in `Target.validate`. Kubernetes secrets, a cloud secret store, or a daemon on the VM would each be one more driver.

## Requirements and limits

- `env-gen` on the machine that runs fleet (or `FLEET_ENVGEN=/path`), with its vault session available (`env-gen unlock`; the session cache is on by default). `fleet` itself talks to no vault API.
- ssh access (`ssh` on the PATH, or `FLEET_SSH=/path`), key-based: fleet runs ssh with `BatchMode=yes`. Remote hosts need a POSIX shell with `cat`, `cp`, `mv`.
- `docker` CLI for docker targets.
- Targets are processed one at a time. Tested on Linux only.
- The first version has no agent: hosts that cannot take inbound ssh are not reachable yet (an agent driver would fit the same interface).
