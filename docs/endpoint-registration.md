# MCP_GATEWAY_SSH_ENDPOINTS

`MCP_GATEWAY_SSH_ENDPOINTS` registers legacy HTTP and WebSocket endpoints that DSH does not expose through its runtime manifest. It is usually unnecessary for current DSH extensions.

Separate entries with commas. Each entry has this form:

```text
[owner:][ws:|http:]path
```

- `owner:` marks an entry as owner-only. Subusers are denied on **both** transports, even with their SSH toggle on.
- `ws:` / `http:` restrict an entry to one transport. With neither prefix, the entry applies to both HTTP and WebSocket.
- Prefixes are optional and order-agnostic (`owner:ws:` is the same as `ws:owner:`).

Examples:

```dotenv
MCP_GATEWAY_SSH_ENDPOINTS=/api/legacy/status,ws:/api/legacy/stream,owner:/api/host/reload
```

## Access rules

A non-`owner:` entry is reachable by a subuser only when **both** conditions hold:

1. the owner (main user) has registered the path in `MCP_GATEWAY_SSH_ENDPOINTS`, and
2. the subuser's **SSH permission** toggle is enabled.

The toggle is a single switch covering both HTTP and WebSocket, and revoking it takes effect immediately. Official terminal access also uses that toggle. Registered third-party Remote mux streams remain owner-only. The owner (main user) is not restricted by this table.

## Path matching

- A path without a wildcard matches exactly.
- A trailing `/*` matches **direct child paths only**. It does not grant the base path itself and does not match deeper nested paths. `/api/plugin/*` allows `/api/plugin/terminal`, but not `/api/plugin` or `/api/plugin/a/b`.
- Unregistered third-party paths keep the gateway's generic posture: ordinary third-party HTTP requests (for example `/api/*` and root-level plugin routes) are forwarded to the upstream for subusers, subject to the blocked host namespaces and object-level session/workspace authorization. Unregistered third-party WebSocket upgrades stay fail-closed for subusers.

## Methods

Registration grants the whole path regardless of HTTP method: the gateway does not subdivide an entry by method. Register the minimal set you actually intend to expose. HTTP write requests to registered endpoints that carry a `host` field are still subject to SSRF validation.

## Reserved paths

Gateway-internal paths cannot be registered: `/gateway` and everything under `/gateway/`, plus `/api/dsh-passwords/internal` and its subtree.

## Hot reload

When `DSH_PASSWORDS_ENV_FILE` points to the active configuration file, the gateway re-reads this table every 5 seconds and applies changes without a restart. Clearing the table tightens access immediately and disconnects WebSockets that were authorized through the registry. An invalid entry rejects the whole table and the last valid one is kept (the gateway logs the error once); it is never silently widened.

Without an explicit `DSH_PASSWORDS_ENV_FILE`, restart the gateway after editing `.env`.
