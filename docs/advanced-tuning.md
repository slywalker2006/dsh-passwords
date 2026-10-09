# Advanced Tuning

These settings are optional operational overrides. Normal installations should leave them unset; the built-in defaults are the supported values. Existing values in a deployment `.env` remain supported and are not changed automatically.

## Remote mux

| Variable | Default | Range | Purpose |
|---|---:|---:|---|
| `MCP_GATEWAY_MUX_FRAGMENT_BYTES` | `131072` | `0` or `16384..1048576` | UTF-8 byte fragment size; `0` keeps single-frame sending without drain polling |
| `MCP_GATEWAY_MUX_PING_INTERVAL_MS` | `2000` | `250..60000` | Ping interval |
| `MCP_GATEWAY_MUX_PONG_TIMEOUT_MS` | `30000` | `2000..600000` | Matched-Pong deadline after local Ping write |
| `MCP_GATEWAY_MUX_WRITE_STALL_MS` | `30000` | `5000..600000` | Local write-stall and queued-Ping deadline |

Values are strict decimal integers. Blank or unset values use defaults. Invalid or out-of-range values fall back to defaults with a warning. If the Ping interval exceeds the Pong timeout, both validated values are retained and a warning is emitted.

## Gateway and inventory timeouts

| Variable | Default | Range | Purpose |
|---|---:|---:|---|
| `MCP_GATEWAY_INTERNAL_PROBE_TIMEOUT_MS` | `10000` | `1000..600000` | Internal DSH/plugin probe timeout |
| `MCP_GATEWAY_UPSTREAM_HEADER_TIMEOUT_MS` | `60000` | `1..600000` | Upstream response-header timeout |
| `MCP_DSH_PASSWORDS_INVENTORY_TTL_MS` | `0` | `0..600000` | Optional inventory cache TTL; concurrent misses are coalesced even when TTL is `0` |

These variables are compatibility overrides for operators. They are not required for ordinary users.

## Directory picker roots

| Variable | Default | Range | Purpose |
|---|---|---|---|
| `MCP_GATEWAY_DIRECTORY_PICKER_ROOTS` | unset ⇒ `os.homedir()` | comma- or newline-separated absolute paths; filesystem roots and relative paths are dropped | Starting points the owner's restricted directory picker may browse when assigning a subuser's readable directories |

When unset or blank, the only starting point is the user home. A filesystem root (`/` or a drive root) is never a starting point and is discarded during parsing, so the picker never enumerates the whole disk. Each candidate is re-validated against the live filesystem (existing directory, non-sensitive, not a filesystem root); a failing candidate is dropped rather than widened to a broader path. This variable controls the owner's picker only; a subuser browses within its own readable directories (`allowedFolders`).

## Applying changes

These overrides are read when the gateway starts. Unlike `MCP_GATEWAY_SSH_ENDPOINTS`, which the gateway re-reads every 5 seconds (see [endpoint registration](endpoint-registration.md)), changing them requires a restart.

On a host installation, restart the gateway after editing `.env`. For Docker, recreate the container with the original Compose file:

```sh
docker compose up -d --force-recreate dsh-passwords
```

Do not put credentials, cookies, tokens, or message contents in these settings.
