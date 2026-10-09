# dsh-passwords

[简体中文](README.md) | English

<p align="center">
  <img src="docs/banner.jpg" alt="dsh-passwords" width="100%">
</p>

<p align="center">
  <a href="https://github.com/slywalker2006/dsh-passwords/releases/latest"><img src="https://img.shields.io/github/v/release/slywalker2006/dsh-passwords?style=flat-square" alt="Version"></a>
  &nbsp;
  <a href="https://github.com/slywalker2006/dsh-passwords/stargazers"><img src="https://img.shields.io/github/stars/slywalker2006/dsh-passwords?style=flat-square" alt="Stars"></a>
  &nbsp;
  <a href="https://www.npmjs.com/package/dsh-passwords"><img src="https://img.shields.io/npm/v/dsh-passwords?style=flat-square" alt="npm"></a>
  &nbsp;
  <a href="https://www.npmjs.com/package/dsh-passwords"><img src="https://img.shields.io/npm/dm/dsh-passwords?style=flat-square" alt="Downloads"></a>
  &nbsp;
  <a href="https://github.com/slywalker2006/dsh-passwords/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/slywalker2006/dsh-passwords/ci.yml?style=flat-square&label=CI" alt="CI"></a>
  &nbsp;
  <a href="https://github.com/deepseek-ai/deepseek-harness"><img src="https://img.shields.io/badge/DSH-0.2.1--alpha.2-4c6ef5?style=flat-square&labelColor=454a54" alt="DSH"></a>
  &nbsp;
  <img src="https://img.shields.io/badge/license-GPL--3.0-blue?style=flat-square" alt="License">
  &nbsp;
  <a href="https://github.com/awesome-dsh-plugin/awesome-dsh-plugin"><img src="https://img.shields.io/badge/Awesome-DSH%20Plugin-9370db?style=flat-square" alt="Awesome DSH Plugin"></a>
  &nbsp;
  <a href="https://github.com/0xsline/awesome-deepseek-harness"><img src="https://img.shields.io/badge/Awesome-DeepSeek%20Harness-4c6ef5?style=flat-square" alt="Awesome DeepSeek Harness"></a>
  &nbsp;
  <a href="https://github.com/Zhiyuan-Fan/Awesome-DeepSeek-Harness-Plugins"><img src="https://img.shields.io/badge/Featured-Awesome%20Plugins-15aabf?style=flat-square" alt="Featured on Awesome DeepSeek Harness Plugins"></a>
  &nbsp;
  <a href="https://github.com/bruc3van/awesome-dsh-plugin"><img src="https://img.shields.io/badge/Featured-DSH%20Catalog-1c7ed6?style=flat-square" alt="Featured on DSH Catalog"></a>
  &nbsp;
  <a href="https://github.com/imsai-sh/awesome-deepseek-harness-plugins"><img src="https://img.shields.io/badge/Featured-1024%20Store-0ca678?style=flat-square" alt="Featured on 1024 Plugin Store"></a>
</p>

<p align="center">
  <strong>Let people share DeepSeek Harness remotely, with per-user workspace, session and usage controls</strong><br>
  <em>Accounts · Workspace and session grants · Usage caps · Audit log · Bilingual UI</em>
</p>

<div align="center">

[When to use it](#when-to-use-it) · [Features](#features) · [Quick start](#quick-start) · [First-run setup](#first-run-setup) · [Uninstall](#uninstall) · [Automatic HTTPS](#automatic-https) · [Deployment topologies](#deployment-topologies) · [Configuration](#configuration-reference) · [FAQ](#faq) · [Security](#security-and-privacy) · [Contributing](#contributing)

</div>

---

## When to use it

- **A small team sharing a server**: give each person an account and assign the workspaces and sessions they can access.
- **An owner sharing selected work**: grant access to chosen workspaces and sessions rather than exposing the entire DSH instance.
- **Managed remote access**: set per-user usage limits, control file and terminal access, and review audit records.

## Features

- **Login**: first-run setup creates the owner account; the gateway requires login for the web UI and protected APIs; sessions last 12 hours
- **Automatic HTTPS**: host deployments can issue and renew Let's Encrypt certificates when public ports 80/443 are reachable; Docker uses HTTP by default, with HTTPS provided by an outer reverse proxy
- **Accounts**: one owner plus subusers; account management lives in the dsh settings page
- **Permissions and quotas**: directory allowlists (readable directories, `allowedFolders`), per-session toggles, hourly token caps, daily time caps, three sandbox tiers, upload/download switches, SSH/terminal switch, ban
- **Session grants**: workspace permission no longer implies access to every session; the owner grants sessions individually; archive state stays consistent between workspace and session lists
- **Operator view**: the owner sees all workspaces and sessions and can download non-sensitive regular files
- **Auditing and security**: login rate limiting and lockout, audit log, encryption of sensitive SQLite fields, bcrypt password hashes, logout revokes sessions
- **Settings card**: patch reload, software updates, account and permission management, in-app messaging, bilingual zh/en UI

## Screenshots

| Account management | Workspace, session and usage controls |
|:---:|:---:|
| <img src="https://raw.githubusercontent.com/slywalker2006/dsh-passwords/main/docs/screenshots/card-front.png" width="480"> | <img src="https://raw.githubusercontent.com/slywalker2006/dsh-passwords/main/docs/screenshots/card-back.png" width="480"> |

| dsh main UI · signed in | Chat / Messaging |
|:---:|:---:|
| <img src="https://raw.githubusercontent.com/slywalker2006/dsh-passwords/main/docs/screenshots/main-ui.png" width="480"> | <img src="https://raw.githubusercontent.com/slywalker2006/dsh-passwords/main/docs/screenshots/chat.png" width="480"> |

| Login · Light | Login · Dark | Login · English |
|:---:|:---:|:---:|
| <img src="https://raw.githubusercontent.com/slywalker2006/dsh-passwords/main/docs/screenshots/white-login.png" width="360"> | <img src="https://raw.githubusercontent.com/slywalker2006/dsh-passwords/main/docs/screenshots/black-login.png" width="360"> | <img src="https://raw.githubusercontent.com/slywalker2006/dsh-passwords/main/docs/screenshots/white-login-en.png" width="360"> |

## Quick start

### Prerequisites

- **Docker**: Docker Engine or Docker Desktop and a DeepSeek API key. DSH and Node.js are bundled; host installations of them are not required.
- **Host install**: Node.js 22.19+ within 22.x, or 24+, a working DSH installation, git and pnpm. Node.js 23 is not supported. The one-liner installer installs pnpm automatically; manual registration uses `node scripts/register-plugin.mjs`.

The compatibility gate accepts the DSH `0.2.1` patch line, `>=0.2.1-alpha.1 <0.2.2-0`. Development and bundled Docker use `0.2.1-alpha.2`. Acceptance by the version gate does not mean every version in the range has been verified at runtime; see [Version compatibility](#version-compatibility).

The current release is `2.7.8`, and the Docker image bundles DSH `0.2.1-alpha.2`; for a source checkout, use the version in [package.json](package.json).

### Recommended: Docker

Start the container with the following Bash command, replacing both example keys:

```bash
docker run -d \
  --name dsh-passwords \
  --restart unless-stopped \
  -e DEEPSEEK_API_KEY=sk-your-key \
  -e SETUP_KEY=your-own-strong-random-string \
  -p 127.0.0.1:3088:3088 \
  -v dsh-home:/data/dsh \
  -v dsh-passwords-state:/data/dsh-passwords \
  skywalker237234/dsh-passwords:2.7.8
```

PowerShell equivalent (one line):

```powershell
docker run -d --name dsh-passwords --restart unless-stopped -e DEEPSEEK_API_KEY=sk-your-key -e SETUP_KEY=your-own-strong-random-string -p 127.0.0.1:3088:3088 -v dsh-home:/data/dsh -v dsh-passwords-state:/data/dsh-passwords skywalker237234/dsh-passwords:2.7.8
```

Open `http://127.0.0.1:3088` **on the Docker host**, enter your `SETUP_KEY`, create the owner account, then sign in. If Docker runs on a remote server, use an SSH port forward to reach this local address or configure an HTTPS reverse proxy before accessing it remotely.

If you omit `-e SETUP_KEY`, the container generates a key. Read it before completing setup:

```bash
docker exec dsh-passwords cat /data/dsh-passwords/setup-key.txt
```

When initializing a new state volume, the container writes the provided `SETUP_KEY` into its `.env`. Changing this environment variable does not recreate existing accounts. Docker runtime environment values still take precedence over corresponding values in the volume's `.env`, so keep the deployment configuration consistent. After setup, sign in with the account you created.

The [v2.7.8 release notes](https://github.com/slywalker2006/dsh-passwords/releases/tag/v2.7.8) record first-run setup and login verification for this release. After setup, confirm `/gateway/healthz` and `/gateway/readyz` return `ok:true`, and check login and subuser permissions.

<details>
<summary><strong>Advanced Docker configuration and data</strong></summary>

For custom ports, domains, SSH endpoints or third-party endpoint registration, copy [docker/.env.example](docker/.env.example) to `docker/.env` and add `--env-file docker/.env` to `docker run`. For Compose:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml up -d
```

Use the Docker template rather than the host [.env.example](.env.example). Docker defaults to HTTP on port `3088`; the host template is intended for automatic HTTPS on `443` and uses different state paths. Mixing the templates can prevent startup or leave the published port disconnected from the gateway.

For public access, terminate HTTPS at nginx, Caddy or another reverse proxy and forward to `http://127.0.0.1:3088`. Preserve the external Host header and forward WebSocket connections. Set `MCP_GATEWAY_PUBLIC_HOST` to the domain you use. The command above publishes only the host's loopback address; the container listens on `0.0.0.0:3088`.

- The two named volumes hold the DSH profile and gateway configuration, database and certificates. Keep them persistent; see [Uninstall](#uninstall) for cleanup.
- For split-container deployments, set `MCP_DSH_PATCH_ALLOW_BIND_ALL=1` on the DSH container so the gateway container can reach DSH web. The bundled `dsh-web-app` in `0.2.1-alpha.2` still needs this patch for `--host 0.0.0.0`.

</details>

### Host installation

Choose one of the following four paths. The installer installs dependencies, builds, generates or fills in missing keys, registers the plugin precisely, and applies the remote-settings patch. It preserves existing configuration on repeated runs, but may update managed keys and configuration entries.

> Use the installer or `node scripts/register-plugin.mjs` for registration. Do not use `dsh plugin add`: it can register dependency bundles too and cause a duplicate loader entry.

**1. Linux / macOS one-liner**

```bash
curl -fsSL https://raw.githubusercontent.com/slywalker2006/dsh-passwords/main/install.sh | sudo bash
```

This download-based installation defaults to `/opt/dsh-passwords` (a non-root user defaults to `$HOME/dsh-passwords` instead, since `/opt` needs root); override either with `DSH_PASSWORDS_DIR`. The installer resumes in a recognized existing dsh-passwords directory and aborts for an unrelated existing target.

**2. Clone, then install**

```bash
git clone https://github.com/slywalker2006/dsh-passwords && cd dsh-passwords
sudo bash install.sh
```

This path installs in the current source directory, which can hold long-lived configuration and data.

**3. Global npm install or upgrade**

First install:

```bash
npm install -g dsh-passwords@2.7.8
sudo dsh-passwords install
```

Omit `sudo` on Windows. To upgrade an earlier installation, update the global package and rerun `dsh-passwords install` to register the plugin and apply the patch; existing `.env` and database files are kept.

A global npm directory is replaced during upgrades. Keep `DSH_PASSWORDS_ENV_FILE` in a stable location for long-lived deployments, or use the Git installation path. With `nvm` or Homebrew, Node may not be available in `sudo`'s PATH.

**4. Windows installer**

Download [install.bat](install.bat) from the repository and run it. This download-based installation defaults to `%USERPROFILE%\dsh-passwords`.

When a host installer creates a new setup key or fills in a missing one, it prints the key and writes it to `setup-key.txt` in the installation directory. A repeated installation with existing keys does not print them again. Use the existing key or account for that deployment.

### First-run setup

1. **Host installs**: start DSH with `dsh web`. Docker starts DSH automatically.
2. Open the address for your deployment:

   | Deployment | Address |
   |---|---|
   | Host with automatic HTTPS | The printed HTTPS URL using your domain or `<public IP>.sslip.io` |
   | Docker on the same computer | `http://127.0.0.1:3088` |
   | HTTPS reverse proxy | Your configured HTTPS domain |
   | HTTP script | The address printed by `scripts/start-http.mjs` |

3. Enter the setup key and create the owner account. Then sign in with that account.
4. Create a subuser in the settings card, assign workspace and session access, and confirm the account sees only its granted resources.

After successful first-run setup, the standard flow deletes `setup-key.txt` and rotates `SETUP_KEY` in `.env`. Existing session, internal API and database encryption settings are preserved. For custom deployments, ensure `.env` is writable and back it up together with the database.

## Uninstall

For a host installation, run this from the dsh-passwords installation directory:

```bash
node dist/cli.js uninstall
# A global npm installation can also use:
dsh-passwords uninstall
```

The command removes only the `dsh-passwords` link and bundle from the DSH web profile, then rolls back dsh patches managed by this plugin. Other plugins and bundles remain in place. Restart `dsh-web` when prompted.

It does not delete the installation directory, `.env`, database, TLS/ACME certificates, or other plugins. If profile dependency reconciliation or patch rollback fails, the original profile is restored to avoid a partial uninstall. For Docker, stop and remove the deployment using its Compose or container configuration; do not remove named volumes unless you also intend to permanently erase data.

Emergency cleanup does not self-delete from inside Docker. To permanently clear all container data, Compose users can run `docker compose down -v`. For the documented `docker run` deployment, run `docker rm -f dsh-passwords`, then `docker volume rm dsh-home dsh-passwords-state`. These commands remove the data volumes; back up the data first.

## Automatic HTTPS

Host installations enable automatic HTTPS by default. With public ports 80/443 reachable, the gateway detects the public IP and requests a Let's Encrypt certificate for `<IP>.sslip.io`. For your own domain, set `MCP_GATEWAY_DOMAIN` and point its DNS to the server. Docker defaults to HTTP behind an HTTPS reverse proxy; see [Deployment topologies](#deployment-topologies).

Renewal follows the certificate's actual expiry date: the gateway checks daily and renews when no more than 30 days remain, then reloads the certificate. Initial issuance failure prevents startup rather than falling back to HTTP; renewal failure retains the existing certificate and retries in the background.

| Code | Meaning | Action |
|---|---|---|
| 30 | Certificate issuance failed | Check 80/443 availability and that Let's Encrypt is reachable |
| 31 | No public IP or domain | Set `MCP_GATEWAY_DOMAIN`, or use HTTP mode |
| 32 | Port occupied | Change `MCP_GATEWAY_PORT` or free the port |

This implementation requests a DNS-name certificate using `<IP>.sslip.io` or your configured domain. Use that HTTPS hostname rather than the bare IP to avoid a hostname mismatch. The port 80 redirect points to the corresponding HTTPS hostname.

## Deployment topologies

| Scenario | Approach |
|---|---|
| Public host installation with 80/443 open | Default host configuration, automatic HTTPS |
| Existing domain certificate | Set `MCP_GATEWAY_TLS_CERT` / `MCP_GATEWAY_TLS_KEY`; port 80 not needed |
| Existing nginx / Caddy reverse proxy | Terminate HTTPS at the proxy, preserve the external Host header and forward WebSocket connections; for a host gateway set `MCP_GATEWAY_AUTO_TLS=0`, `MCP_GATEWAY_HOST=127.0.0.1` and `MCP_GATEWAY_PORT=8080`; for Docker use the published `127.0.0.1:3088` |
| Cloudflare | Use an HTTPS origin reverse proxy, or Cloudflare Tunnel with a locally reachable gateway; configure the origin according to the chosen method |
| Local or internal deployment | Use explicit HTTP mode; use HTTPS when transmitting login credentials across a network |

Automatic HTTPS uses http-01 validation and requires public port 80 for issuance and renewal. Keep it reachable for renewals; their schedule follows the certificate expiry date. A Cloudflare Tunnel can connect to a local HTTP gateway without opening public port 80. If Cloudflare proxies a domain used for automatic HTTPS, ensure the ACME challenge reaches the origin.

## HTTP mode

Host installations enable automatic HTTPS by default. Docker explicitly disables it and serves HTTP behind the outer proxy. For local or internal host use, start HTTP mode explicitly:

```bash
node scripts/start-http.mjs [port] [host]    # defaults to 127.0.0.1:8080; asks for confirmation
```

For a persistent host configuration, set `MCP_GATEWAY_AUTO_TLS=0`, `MCP_GATEWAY_HOST=127.0.0.1` and `MCP_GATEWAY_PORT=8080` in `.env`. The host setting matters: disabling TLS alone does not change the default listen address to loopback. Pass another host to the script only when you intend to make the HTTP service reachable from that network.

HTTP mode needs no public IP, DNS or ACME. The initial installation still needs npm/GitHub access, or a prepared project tarball, dependency cache and local DSH installation. Model replies require an upstream provider such as `DEEPSEEK_API_KEY`; without a model service, login, permissions, files and administration remain available but model generation does not.

## The gate card in dsh settings

After signing in, open Settings to find the "dsh-passwords" card.

| Feature | Who | Notes |
|---|---|---|
| Patch reload | Owner only | Re-applies the patch and restarts the web service when a dsh upgrade breaks the settings page |
| Software updates | Status visible to all, actions owner only | Auto check, throttled download, idle-window install and restart, see below |
| Change password / username | Self; owner can act on anyone | Password change revokes all old sessions |
| Subuser management | Owner only | Create and delete subusers |
| Subuser permissions | Owner only | Directory allowlist (readable directories, assigned with the restricted directory browser), per-session grants, token and time caps, sandbox tier, upload/download switches, SSH/terminal switch (off by default; explicit owner grant; revocation immediate), WebSocket path grants, ban |
| Chat / messaging | All signed-in users | Tagged messages; subuser messages default to DMs to the owner, only the owner can broadcast |
| Sign out | All signed-in users | Ends the current session |

Subuser directory permissions: the directory scope is decided solely by "Readable directories" (`allowedFolders`), which the owner assigns with the restricted directory browser. The browser browses only within its configured starting points, which come from `MCP_GATEWAY_DIRECTORY_PICKER_ROOTS`, defaulting to the user home when unset; a filesystem root is never used as a starting point, so the whole disk is never enumerated. A folder inside the allowlist is readable; with "Workspace creation permission" enabled, those same readable folders are also the creation scope, so the subuser can create new folders there and register their newly created folders as workspaces; a folder outside the allowlist is neither readable nor creatable. An empty allowlist ("All directories") keeps the existing unrestricted-directory semantics; the `['__deny__']` sentinel denies all directories. Turning "Workspace creation permission" off only denies creation and preserves the readable scope. Both lexical and real paths are checked to reject symlink escapes and other subusers' workspace subtrees.

Passwords require at least 12 characters with upper, lower, digit and symbol.

## Software updates

- Version discovery uses GitHub Releases; packages always come from the npm registry, verified against the release's `dist.integrity` sha512
- Automatic mode: checks every 24 hours, downloads throttled after finding a new version, installs and restarts after the platform has been idle for one hour; the owner can install immediately
- Manual mode: check only discovers versions; the first click downloads, the second click installs and restarts
- Installs preserve `.env`, `data/`, the database, TLS material and the dsh profile; failures roll back
- Docker updates require explicit `MCP_DSH_DOCKER_SELF_UPDATE=1` plus the Compose variables; without them only host-side manual commands are shown. A Docker socket grants the container control of the host; enable only in trusted deployments

## Configuration reference

| Variable | Default | Description |
|---|---|---|
| `SETUP_KEY` | Generated by the install script (Docker can set it with `-e SETUP_KEY`) | First-run setup key; rotated automatically after setup succeeds |
| `MCP_JWT_SECRET` | Derived from SETUP_KEY | Session signing key; set independently with `openssl rand -hex 32` in production |
| `MCP_INTERNAL_SECRET` | Derived from SETUP_KEY | Gateway internal admin-API secret (used by the dsh plugin to notify the gateway), derived in a separate domain from the JWT; do not rotate it casually once set |
| `MCP_DB_PATH` | Host `./data/platform.db`; Docker `/data/dsh-passwords/platform.db` | SQLite database path; a relative path is anchored to the directory of the `.env` (the `DSH_PASSWORDS_ENV_FILE` directory), not the process working directory |
| `MCP_DB_ENC_KEY` | Generated by installers; when unset in a manual deployment, uses `SETUP_KEY` as the master secret for key derivation | Encrypts sensitive database fields. After standard setup, the effective value is preserved as an independent variable. Do not change it for an existing database without a migration; back up the database together with `.env` |
| `MCP_GATEWAY_HOST` / `MCP_GATEWAY_PORT` | `0.0.0.0` / host automatic HTTPS `443`; HTTP script `127.0.0.1:8080`; Docker `0.0.0.0:3088` | Gateway listen address and port. Docker defaults can be overridden; keep the container port and published mapping consistent. The example maps Docker to host loopback `127.0.0.1:3088` |
| `MCP_GATEWAY_UPSTREAM` | `http://127.0.0.1:3080` | dsh web address, pointed automatically |
| `MCP_GATEWAY_UPSTREAM_TLS_VERIFY` | on | Verify the upstream dsh certificate when it is HTTPS/WSS; `0` disables it (debugging only, never in production) |
| `MCP_GATEWAY_SSH_ENDPOINTS` | empty | Registers legacy HTTP/WS endpoints DSH does not surface. See [endpoint registration](docs/endpoint-registration.md) for syntax and access rules. |
| `MCP_GATEWAY_REDIRECT_PORT` | `80` with automatic HTTPS; not listening when it is off | ACME validation and 301 redirect port; an explicit `0` disables it |
| `MCP_GATEWAY_DOMAIN` | empty | Custom domain; empty uses `<public IP>.sslip.io` |
| `MCP_GATEWAY_AUTO_TLS` | on for host installs; Docker defaults to `0` | `0` disables automatic HTTPS. Docker uses HTTP with an outer reverse proxy for HTTPS by default; overriding this requires the corresponding certificate and port configuration |
| `MCP_GATEWAY_TLS_CERT` / `MCP_GATEWAY_TLS_KEY` | empty | Your own certificate, takes precedence over automatic HTTPS |
| `MCP_GATEWAY_PUBLIC_HOST` | empty | Fixed redirect target, guards against Host spoofing |
| `MCP_GATEWAY_ACME_EMAIL` / `MCP_GATEWAY_ACME_STAGING` | empty / off | Renewal contact email / LE staging |
| Advanced tuning | Built-in defaults are validated for ordinary installations; operational overrides are documented in [`docs/advanced-tuning.md`](docs/advanced-tuning.md). Normal users do not need to set them |
| `MCP_DSH_ROOT` | auto-detected | dsh installation directory |
| `MCP_DSH_SETTINGS_FILE` | auto-detected | Path to the dsh `settings.yaml`; set it explicitly when the gateway and dsh are not on the same machine. Empty probes candidates such as `DSH_HOME/settings.yaml` |
| `MCP_DSH_RESTART_SERVICE` | Linux `dsh-web`; Windows empty | systemd service restarted after patch reload; on Windows, restart DeepSeek Harness manually after an update |
| `MCP_DSH_AUTO_UPDATE` | on | Deployment-level auto-update master switch |
| `MCP_DSH_UPDATE_MAX_BPS` | 1MiB/s | Automatic download throttle; can only be lowered |
| `MCP_DSH_DOCKER_SELF_UPDATE` / `_COMPOSE_DIR` / `_COMPOSE_FILE` / `_IMAGE` / `_SOCKET` | off / empty | Docker in-app update switch and Compose settings |
| `MCP_DSH_PATCH_ALLOW_BIND_ALL` | off | Allows dsh web to bind 0.0.0.0 for split-container topologies (`dsh-web-app` in `0.2.1-alpha.2` still needs the sub-patch) |
| `DSH_PASSWORDS_ENV_FILE` | empty | Explicit `.env` path |

Configuration precedence differs by install method: Docker environment settings, including `SETUP_KEY`, override corresponding settings in the volume's `.env`; on a host, managed keys in the deployment `.env` take precedence over inherited variables. Initializing a new Docker state volume writes the supplied setup key into `.env`; changing the environment variable does not recreate existing accounts or remove runtime environment precedence.

Advanced Remote mux, gateway timeout, and inventory overrides, including compatibility parsing and restart behavior, are documented in [`docs/advanced-tuning.md`](docs/advanced-tuning.md). Normal users do not need to configure them; existing deployment overrides remain supported and are not changed automatically.

## Common commands

```bash
node dist/cli.js audit --limit 20        # last 20 audit entries
node dist/cli.js patch status            # remote-settings patch status
node dist/cli.js patch                   # reload patch and restart dsh-web
node dist/cli.js serve-gateway --port 9000   # change the port; retains configured TLS mode
DSH_PASSWORDS_NO_AUTOSTART=1 dsh web     # keep the gateway from auto-starting
curl -s https://address/gateway/healthz      # liveness check
curl -s https://address/gateway/readyz       # readiness check, includes database
```

## FAQ

<details>
<summary><strong>The login page keeps showing first-run setup</strong></summary>

The users table is empty; enter the SETUP_KEY to recreate the owner account.

</details>

<details>
<summary><strong>Forgot the owner password</strong></summary>

Stop the service, clear the users table and restart:

```bash
node -e "const {DatabaseSync}=require('node:sqlite');const db=new DatabaseSync('data/platform.db');db.exec('DELETE FROM users;')"
```

</details>

<details>
<summary><strong>Exit codes 30 / 31 / 32</strong></summary>

See the table under "Automatic HTTPS".

</details>

<details>
<summary><strong>Binding 443 fails as non-root</strong></summary>

Ports below 1024 require root on Linux; switch to a high `MCP_GATEWAY_PORT` and forward as needed. A non-root first install also has to disable automatic HTTPS explicitly (`MCP_GATEWAY_AUTO_TLS=0`) or supply your own certificate, otherwise the installer asks for root. The download-based default directory moves from `/opt` to `$HOME/dsh-passwords`; point `DSH_PASSWORDS_DIR` at another writable path if you prefer.

</details>

<details>
<summary><strong>dsh reports duplicate loader entry id</strong></summary>

`dsh plugin add` adds every bundle-declaring dependency to the bundles layer and conflicts. Uninstall and register precisely with `node scripts/register-plugin.mjs`.

</details>


<details>
<summary><strong>Is a stolen database file a problem</strong></summary>

Yes. Sensitive fields are encrypted and passwords are stored as bcrypt hashes, but an attacker can still attempt offline password guessing and read unencrypted database metadata. Encryption also depends on protecting the effective key, normally stored in `.env`. Keep database backups and key files private, and treat theft of both as a compromise.

</details>

<details>
<summary><strong>Can MCP_DB_ENC_KEY be rotated</strong></summary>

There is no built-in key migration. Do not directly change the effective key for an existing database: previously encrypted fields would become unreadable. In a manual deployment before first-run setup, if `MCP_DB_ENC_KEY` is unset, `SETUP_KEY` is also the database's master secret; do not change it once encrypted data exists. A rotation would require decrypting and re-encrypting those fields through a separately verified migration. Back up the database and its current key before any such work.

</details>

<details>
<summary><strong>Plugin loading is slow / access feels slow</strong></summary>

The gateway gives content-hashed static assets a one-year cache lifetime. A first visit or upgrade may download new assets; later visits can reuse the cache, depending on the browser and proxy. Actual response time depends on the network, TLS, gateway, DSH and model provider. Measure your deployment before identifying the bottleneck; for example, check the TLS handshake:

```bash
curl -so /dev/null -w "TLS:%{time_appconnect}s\n" https://address/gateway/login
```

Compare this with total request time and the time taken by DSH or the model provider.

</details>

## Manual install

Use Node.js `22.19+` within 22.x, or `24+`, with an existing DSH installation in the accepted `0.2.1` range. Node.js 23 is not supported. Registration requires pnpm. See [Version compatibility](#version-compatibility) for the pinned runtime and the scope of release verification.

1. `git clone https://github.com/slywalker2006/dsh-passwords && cd dsh-passwords`
2. `npm install && npm run build`
3. `cp .env.example .env` and set SETUP_KEY to `openssl rand -hex 24`
4. `node scripts/register-plugin.mjs` to register the plugin
5. `node dist/cli.js patch` to apply the patch; set `MCP_DSH_ROOT` if the dsh directory is not found

Then start dsh, the gateway comes up automatically, and "First-run setup" finishes initialization.

## Security and privacy

Passwords are stored as bcrypt hashes and sensitive fields are encrypted in SQLite. This is field encryption rather than encryption of the entire database file; metadata can remain readable. Protect the database, `.env` and backups. With automatic HTTPS enabled, initial certificate issuance failure prevents the gateway from starting.

- Failed-login lockout backs off per round from 1 to 60 minutes; the owner account cannot be globally locked out by rotating IPs
- 30 failures from one IP within 15 minutes trigger a 30-minute IP-level throttle, countering cross-username password spraying
- Logout revokes the token server-side; password and username changes invalidate all old sessions
- Third-party plugin operator endpoints are owner-only; SSH/terminal access is off by default and requires an explicit owner grant (revocation is immediate); uploads and downloads are permission-gated and new subusers start with downloads disabled
- Request timeouts and connection limits mitigate slowloris; path normalization blocks `%2f` and double-encoding variants
- With an existing, writable `.env`, standard first-run setup deletes `setup-key.txt`, preserves the effective secrets as independent variables and rotates `SETUP_KEY`; check the result for custom deployments

## Language

The UI is bilingual zh/en and follows the dsh language setting. The login page has a manual switch that persists; the CLI follows `LANG` / `LC_ALL`.

## Version compatibility

- **Plugin version**: the published release and Docker image are `2.7.8` (DSH `0.2.1-alpha.2`).
- **DSH version gate**: accepts only `>=0.2.1-alpha.1 <0.2.2-0`, including later `0.2.1` prereleases and stable `0.2.1`. It rejects `0.1.x`, `0.2.0`, `0.2.1-alpha.0` and all `0.2.2+` identities.
- **Pinned runtime**: development dependencies and bundled Docker use DSH `0.2.1-alpha.2`. A version accepted by the range is not automatically verified at runtime.
- **Upgrade from 2.7.7**: update the package or source checkout, rerun the installer, and restart DSH; the `.env`, database and DSH profile are retained.

The npm package includes the prebuilt `dist`, installer scripts and linked `docs/` files. Check the matching release notes and image tag when deploying a published version.

## Contributing

- Before opening an issue, read the [community checklist](docs/community-checklist.md) and use the [bug](https://github.com/slywalker2006/dsh-passwords/blob/main/.github/ISSUE_TEMPLATE/bug_report.md) or [feature](https://github.com/slywalker2006/dsh-passwords/blob/main/.github/ISSUE_TEMPLATE/feature_request.md) template
- For code contributions, read [CONTRIBUTING.md](CONTRIBUTING.md) and use the [PR template](https://github.com/slywalker2006/dsh-passwords/blob/main/.github/PULL_REQUEST_TEMPLATE.md); keep changes focused and include test evidence
- Run `npm ci --include=optional && npm run build && node --import tsx --test "test/**/*.test.ts"` before submitting (build first); CI runs automatically on Node 22/24

## Contributors

<a href="https://github.com/slywalker2006/dsh-passwords/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=slywalker2006/dsh-passwords" />
</a>

<div align="center">

**If you find this useful, give it a star.**

[Report an issue](https://github.com/slywalker2006/dsh-passwords/issues) · [Releases](https://github.com/slywalker2006/dsh-passwords/releases) · [npm package](https://www.npmjs.com/package/dsh-passwords) · [Awesome listings](https://github.com/0xsline/awesome-deepseek-harness#security--governance)

</div>

## License

[GNU GPL v3.0 only](https://www.gnu.org/licenses/gpl-3.0.html), full text in [LICENSE](LICENSE).

This project is an independent extension of dsh and is not affiliated with DeepSeek.
