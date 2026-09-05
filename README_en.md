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
  <a href="https://github.com/deepseek-ai/deepseek-harness"><img src="https://img.shields.io/badge/DSH-0.1.2--rc.1-4c6ef5?style=flat-square&labelColor=454a54" alt="DSH"></a>
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
  <strong>A server-grade authentication gateway that turns DeepSeek Harness into a multi-tenant platform</strong><br>
  <em>Login · Auto HTTPS · Multi-tenant permissions · Session grants · Audit & encryption · Bilingual UI</em>
</p>

<div align="center">

[Features](#features) · [Quick start](#quick-start) · [First-run setup](#first-run-setup) · [Uninstall](#uninstall) · [Automatic HTTPS](#automatic-https) · [Deployment topologies](#deployment-topologies) · [Configuration](#configuration-reference) · [FAQ](#faq) · [Security](#security-and-privacy) · [Contributing](#contributing)

</div>

---

The stock dsh web UI has no login or access control. Exposed to a network, anyone with the address can use it. dsh-passwords runs a gateway in front of dsh: unauthenticated visitors only see the login page, and every authenticated request is subject to per-account permissions and quotas. Listed in [Awesome DeepSeek Harness](https://github.com/0xsline/awesome-deepseek-harness#security--governance) (Security & Governance) and [Awesome DSH Plugin](https://github.com/awesome-dsh-plugin/awesome-dsh-plugin#security--permissions) (Security & Permissions).

## Features

- **Login**: first-run setup creates the owner account; every later visit goes through the login page; sessions last 12 hours
- **Automatic HTTPS**: issues and renews Let's Encrypt certificates, redirects port 80 to 443, zero configuration
- **Multi-tenant**: one owner plus any number of subusers; account management lives in the dsh settings page
- **Permissions and quotas**: workspace allowlists, per-session toggles, hourly token caps, daily time caps, three sandbox tiers, upload/download switches, ban
- **Session grants**: workspace permission no longer implies access to every session; the owner grants sessions individually; archive state stays consistent between workspace and session lists
- **Operator view**: the owner sees all workspaces and sessions and can download non-sensitive regular files
- **Auditing and security**: login rate limiting and lockout, audit log, SQLite encryption at rest, logout revokes sessions
- **Settings card**: patch reload, software updates, account and permission management, in-app messaging, bilingual zh/en UI

## Screenshots

| Login · Light | Login · Dark | Login · English |
|:---:|:---:|:---:|
| <img src="docs/screenshots/white-login.png" width="360"> | <img src="docs/screenshots/black-login.png" width="360"> | <img src="docs/screenshots/white-login-en.png" width="360"> |

| dsh main UI · signed in | Chat / Messaging | Settings card · Accounts |
|:---:|:---:|:---:|
| <img src="docs/screenshots/main-ui.png" width="360"> | <img src="docs/screenshots/chat.png" width="360"> | <img src="docs/screenshots/card-front.png" width="360"> |

| | Settings card · Permissions and quotas | |
|:---:|:---:|:---:|
| | <img src="docs/screenshots/card-back.png" width="360"> | |

## Quick start

### Prerequisites

Host installs need Node.js 22.19+ or 24+, a working dsh installation, and git. Keep this plugin on the same Node major line as the dsh host; DSH `0.1.2-rc.1` has the same official Node requirement. Docker installs only need Docker Engine or Docker Desktop and a DeepSeek API key.

### Install

Five install methods, pick one. Host installs automatically install dependencies, build, generate a SETUP_KEY, register the dsh plugin and apply the remote-settings patch; an existing `.env` is never overwritten, so re-running is safe.

```bash
# 1. Linux / macOS one-liner
curl -fsSL https://raw.githubusercontent.com/slywalker2006/dsh-passwords/main/install.sh | bash

# 2. Clone first, then install
git clone https://github.com/slywalker2006/dsh-passwords && cd dsh-passwords
bash install.sh

# 3. npm global install, works on any platform
npm install -g dsh-passwords
dsh-passwords install
```

On Windows download `install.bat` from the repository and run it. The default install directory is `%USERPROFILE%\dsh-passwords`.

```bash
# 4. Docker
docker run -d \
  --name dsh-passwords \
  --restart unless-stopped \
  --env-file .env \
  -p 127.0.0.1:3088:3088 \
  -v dsh-home:/data/dsh \
  -v dsh-passwords-state:/data/dsh-passwords \
  skywalker237234/dsh-passwords
```

`.env` needs at least `DEEPSEEK_API_KEY`. Set `MCP_GATEWAY_PUBLIC_HOST` to the domain you actually use. The container listens on loopback 3088 only; terminate TLS on nginx or Caddy for public access. Initialization is complete once the log shows `dsh patch applied; starting dsh`.

Notes:

- Host installs default to `/opt/dsh-passwords` or `$HOME/dsh-passwords`; override with `DSH_PASSWORDS_DIR`. An existing target directory aborts the installer
- The SETUP_KEY is printed when the install finishes and written to `setup-key.txt` in the install directory
- The two Docker volumes hold the dsh profile and the `.env`, database and certificates; deleting them deletes your data
- For split-container deployments set `MCP_DSH_PATCH_ALLOW_BIND_ALL=1` on the dsh container so the gateway container can reach dsh web

### First-run setup

1. Start dsh: `dsh web`. Docker users skip this; the container starts it automatically.
2. Open `https://<server address>` in a browser; the first visit enters the setup page.
3. Enter the SETUP_KEY to create the owner account. Every later visit to this address goes through the login page.

After setup completes, `setup-key.txt` is deleted automatically and the keys in `.env` are consolidated and rotated.

Docker users need nginx or Caddy to proxy 80/443 to `http://127.0.0.1:3088` first; read the one-time SETUP_KEY with `docker exec dsh-passwords cat /data/dsh-passwords/setup-key.txt`.

## Uninstall

For a host installation, run this from the dsh-passwords installation directory:

```bash
node dist/cli.js uninstall
# A global npm installation can also use:
dsh-passwords uninstall
```

The command removes only the `dsh-passwords` link and bundle from the DSH web profile, then rolls back dsh patches managed by this plugin. Other plugins and bundles remain in place. Restart `dsh-web` when prompted.

It does not delete the installation directory, `.env`, database, TLS/ACME certificates, or other plugins. If profile dependency reconciliation or patch rollback fails, the original profile is restored to avoid a partial uninstall. For Docker, stop and remove the deployment using its Compose or container configuration; do not remove named volumes unless you also intend to permanently erase data.

## Automatic HTTPS

By default the gateway detects the public IP and issues a 90-day Let's Encrypt certificate for `<IP>.sslip.io`, renewing automatically 30 days before expiry with hot reload. For your own domain set `MCP_GATEWAY_DOMAIN`. Issuance failure refuses to start and never falls back to plaintext; renewal failure keeps the still-valid old certificate and retries in the background.

| Code | Meaning | Action |
|---|---|---|
| 30 | Certificate issuance failed | Check 80/443 availability and that Let's Encrypt is reachable |
| 31 | No public IP or domain | Set `MCP_GATEWAY_DOMAIN`, or use HTTP mode |
| 32 | Port occupied | Change `MCP_GATEWAY_PORT` or free the port |

The `<IP>.sslip.io` name exists because Let's Encrypt does not issue certificates for bare IPs. Visiting the bare-IP https address warns about a hostname mismatch; entering through port 80 redirects to the correct address.

## Deployment topologies

| Scenario | Approach |
|---|---|
| Public server with 80/443 open | Default configuration, automatic HTTPS |
| Existing domain certificate | Set `MCP_GATEWAY_TLS_CERT` / `MCP_GATEWAY_TLS_KEY`; port 80 not needed |
| Existing nginx / Caddy reverse proxy | Terminate TLS at the proxy, set `MCP_GATEWAY_AUTO_TLS=0` and a high port, gateway listens on loopback only |
| Cloudflare | CF terminates TLS and forwards to origin, same approach as a reverse proxy |
| Internal network / bare IP without port 80 | Use HTTP mode |

http-01 validation only touches port 80 during issuance and renewal, about once every 60 days.

## HTTP mode

Plaintext HTTP is refused by default. When an internal-only deployment truly needs it:

```bash
node scripts/start-http.mjs [port]    # default 8080, asks for confirmation
```

Or write `MCP_GATEWAY_AUTO_TLS=0` and `MCP_GATEWAY_PORT=8080` into `.env`; the plugin then starts the gateway in HTTP mode.

## The gate card in dsh settings

After signing in, open Settings to find the "dsh-passwords" card.

| Feature | Who | Notes |
|---|---|---|
| Patch reload | Owner only | Re-applies the patch and restarts the web service when a dsh upgrade breaks the settings page |
| Software updates | Status visible to all, actions owner only | Auto check, throttled download, idle-window install and restart, see below |
| Change password / username | Self; owner can act on anyone | Password change revokes all old sessions |
| Subuser management | Owner only | Create and delete subusers |
| Subuser permissions | Owner only | Workspace allowlist, per-session grants, token and time caps, sandbox tier, upload/download switches, WebSocket path grants, ban |
| Chat / messaging | All signed-in users | Tagged messages; subuser messages default to DMs to the owner, only the owner can broadcast |
| Sign out | All signed-in users | Ends the current session |

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
| `SETUP_KEY` | Generated by installer | First-run setup key, rotated automatically after setup |
| `MCP_JWT_SECRET` | Derived from SETUP_KEY | Session signing key; set independently with `openssl rand -hex 32` in production |
| `MCP_DB_PATH` | `./data/platform.db` | SQLite database path |
| `MCP_DB_ENC_KEY` | empty | Field encryption key; cannot be changed once set. Back up the database together with `.env` |
| `MCP_GATEWAY_HOST` / `MCP_GATEWAY_PORT` | `0.0.0.0` / `443` | Gateway listen address and port |
| `MCP_GATEWAY_UPSTREAM` | `http://127.0.0.1:3080` | dsh web address, pointed automatically |
| `MCP_GATEWAY_WS_ADMIN_ALLOWLIST` | empty | Third-party WebSocket paths restricted to the owner; exact paths and `/*` wildcards; never shown as subuser grants |
| `MCP_GATEWAY_WS_USER_ALLOWLIST` | empty | Third-party WebSocket paths the owner may grant per subuser; exact paths and `/*` wildcards |
| `MCP_GATEWAY_REDIRECT_PORT` | `80` | ACME validation and 301 redirect port |
| `MCP_GATEWAY_DOMAIN` | empty | Custom domain; empty uses `<public IP>.sslip.io` |
| `MCP_GATEWAY_AUTO_TLS` | on | `0` disables automatic HTTPS |
| `MCP_GATEWAY_TLS_CERT` / `MCP_GATEWAY_TLS_KEY` | empty | Your own certificate, takes precedence over automatic HTTPS |
| `MCP_GATEWAY_PUBLIC_HOST` | empty | Fixed redirect target, guards against Host spoofing |
| `MCP_GATEWAY_ACME_EMAIL` / `MCP_GATEWAY_ACME_STAGING` | empty / off | Renewal contact email / LE staging |
| `MCP_DSH_ROOT` | auto-detected | dsh installation directory |
| `MCP_DSH_RESTART_SERVICE` | `dsh-web` | systemd service restarted after patch reload |
| `MCP_DSH_AUTO_UPDATE` | on | Deployment-level auto-update master switch |
| `MCP_DSH_UPDATE_MAX_BPS` | 1MiB/s | Automatic download throttle; can only be lowered |
| `MCP_DSH_DOCKER_SELF_UPDATE` / `_COMPOSE_DIR` / `_COMPOSE_FILE` / `_IMAGE` / `_SOCKET` | off / empty | Docker in-app update switch and Compose settings |
| `MCP_DSH_PATCH_ALLOW_BIND_ALL` | off | Allows dsh web to bind 0.0.0.0 for split-container topologies |
| `DSH_PASSWORDS_ENV_FILE` | empty | Explicit `.env` path |

## Common commands

```bash
node dist/cli.js audit --limit 20        # last 20 audit entries
node dist/cli.js patch status            # remote-settings patch status
node dist/cli.js patch                   # reload patch and restart dsh-web
node dist/cli.js serve-gateway --port 9000   # start the gateway manually
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

Ports below 1024 require root on Linux; switch to a high `MCP_GATEWAY_PORT` and forward as needed.

</details>

<details>
<summary><strong>dsh reports duplicate loader entry id</strong></summary>

`dsh plugin add` adds every bundle-declaring dependency to the bundles layer and conflicts. Uninstall and register precisely with `node scripts/register-plugin.mjs`.

</details>

<details>
<summary><strong>npm install of dsh fails on node-pty builds</strong></summary>

Allow install scripts and reinstall:

```bash
npm config set allow-scripts=@deepseek-ai/dsh-subprocess-local,koffi,node-pty,@google/genai,protobufjs --location=user
```

</details>

<details>
<summary><strong>Is a stolen database file a problem</strong></summary>

No. Sensitive fields are encrypted or hashed, passwords exist only as bcrypt hashes, and decryption requires the `.env` keys.

</details>

<details>
<summary><strong>Can MCP_DB_ENC_KEY be rotated</strong></summary>

No; changing it makes all existing data undecryptable.

</details>

<details>
<summary><strong>Plugin loading is slow / access feels slow</strong></summary>

The gateway force-caches content-hashed static assets for one year; the first visit after an upgrade downloads fully once, later loads are instant. The gateway adds about 1-2ms per request; check the TLS handshake first:

```bash
curl -so /dev/null -w "TLS:%{time_appconnect}s\n" https://address/gateway/login
```

The bottleneck is usually the network path to the server.

</details>

## Manual install

> The v2.6.10 compatibility layer covers the DSH `0.1.2-alpha.1` through `alpha.5` source runtime and additionally supports `0.1.2-rc.1`. Alpha.1 was never published as an npm package, so the npm/Docker install baseline includes `alpha.2+` and rc.1; this worktree is locked and validated against rc.1. The installers strictly require Node.js `22.19+` or `24.0+`, register the plugin, detect the dsh installation and apply the compatibility patch. Automatic updates and settings-page patch reload use the same patch path.

1. `git clone https://github.com/slywalker2006/dsh-passwords && cd dsh-passwords`
2. `npm install && npm run build`
3. `cp .env.example .env` and set SETUP_KEY to `openssl rand -hex 24`
4. `node scripts/register-plugin.mjs` to register the plugin
5. `node dist/cli.js patch` to apply the patch; set `MCP_DSH_ROOT` if the dsh directory is not found

Then start dsh, the gateway comes up automatically, and "First-run setup" finishes initialization.

## Security and privacy

Passwords are stored only as bcrypt hashes; usernames, IPs and audit records are encrypted at rest; certificate issuance failure refuses to start the gateway.

- Failed-login lockout backs off per round from 1 to 60 minutes; the owner account cannot be globally locked out by rotating IPs
- 30 failures from one IP within 15 minutes trigger a 30-minute IP-level throttle, countering cross-username password spraying
- Logout revokes the token server-side; password and username changes invalidate all old sessions
- Third-party plugin operator endpoints are owner-only; uploads and downloads are permission-gated and new subusers start with downloads disabled
- Request timeouts and connection limits mitigate slowloris; path normalization blocks `%2f` and double-encoding variants
- After first-run setup the system deletes `setup-key.txt` and consolidates independent secret variables automatically

## Language

The UI is bilingual zh/en and follows the dsh language setting. The login page has a manual switch that persists; the CLI follows `LANG` / `LC_ALL`.

## Version compatibility

Current version: 2.6.10. The current development and deployment baseline is DSH `0.1.2-rc.1`; the compatibility layer retains the known DSH `alpha.1` through `alpha.5` layout adapters and has been locally validated against the official rc.1 npm runtime. The npm package ships prebuilt dist, TypeScript sources and all scripts; the bundled Docker image is built from the same source and includes DSH `0.1.2-rc.1`.

## Contributing

- Before opening an issue, read the [community checklist](docs/community-checklist.md) and use the [bug](.github/ISSUE_TEMPLATE/bug_report.md) or [feature](.github/ISSUE_TEMPLATE/feature_request.md) template
- For code contributions, read [CONTRIBUTING.md](CONTRIBUTING.md) and use the [PR template](.github/PULL_REQUEST_TEMPLATE.md); keep changes focused and include test evidence
- Run `npm ci && npm run build && npm test` before submitting; CI runs automatically on Node 22/24

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
