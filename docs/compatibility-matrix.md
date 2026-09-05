# DSH Compatibility Matrix

## Supported baseline

| Component | Supported version | Validation status |
|---|---|---|
| Node.js | 22.19+ or 24+ | Matches the DSH `0.1.2-rc.1` and `0.1.3-alpha.1` engine contracts |
| DSH source/runtime compatibility | `0.1.2` and `0.1.3` | RC.1 npm runtime and alpha.1 source-workspace patch anchors are locally verified |
| Bundled Docker runtime | `0.1.2-rc.1` | Main bundled image target; uses the official npm runtime |
| dsh-passwords | 2.6.11 | Local build, regression suite, official-registry production audit, and package-content checks |


Development dependencies use the latest published RC.1 packages so TypeScript resolves the public plugin APIs. The package does not impose a runtime DSH dependency: DSH owns the profile and loads this package through its plugin link. The compatibility layer supports the `0.1.2` and `0.1.3` API and bundle boundaries.

## Plugin surfaces

| Surface | Status | Requirement |
|---|---|---|
| HTTP UI/API plugins | Code-level compatible | The gateway removes only its own authentication cookie and preserves plugin cookies; validate each third-party plugin in a real alpha.5 profile. |
| Plugin combo URLs | Regression-tested | `/plugins/??...` query bytes, including the second `?`, remain unchanged; alpha.5 combo URL behavior is covered by regression tests. |
| Plugin business `token` query | Regression-tested | Only the alpha index launch-token context strips bare `token`; plugin paths retain it. |
| Third-party WebSocket, administrator | Conditional | Configure `MCP_GATEWAY_WS_ADMIN_ALLOWLIST`. |
| Third-party WebSocket, subuser | Conditional | Configure `MCP_GATEWAY_WS_USER_ALLOWLIST` and grant the path to that user. |
| Unknown WebSocket paths | Not supported | Rejected by default. |
| Alpha Remote mux, subuser `workspace/follow` and `session/control` | Code-level compatible | Gateway applies the existing resource filters; alpha.5 frame handling is covered by Remote mux regression tests. |
| Alpha Remote mux, subuser `session/follow` and `$events` | Regression-tested | `session/follow` accepts ordinary and RC.1 `subagent` addresses; parent access is required, child grants are not; `$events` retains current correlation filtering |
| Directory picker | Native alpha.1+ | dsh-passwords does not insert duplicate official picker loaders. |
| Connection Cookie bridge | Packed-artifact tested | `patch status` must show `patched` or `native`; the gateway refuses startup when the bridge is unavailable. |

## Lifecycle contract

For supported DSH `0.1.2` and `0.1.3` builds, gateway startup is fail-closed: the settings host-mode patch and the authenticated Cookie bridge must both be present. Missing settings exits with code `35`; a missing or unsupported bridge exits with code `33`.

Run `dsh-passwords uninstall` before removing the package directory or running `npm uninstall`. It removes only the `dsh-passwords` link and bundle item from the selected web profile, then rolls back only matching hash-protected patches. It leaves `.env`, `data/`, databases, certificates, and unrelated plugins unchanged. If profile dependency reconciliation or patch rollback fails, it restores the original `package.json`, `pnpm-lock.yaml`, and `node_modules` materialized state. The no-DSH case uses stable exit code `34`, independent of `LANG`; the rc.1 patch and failure paths are covered locally, while real server HTTPS and browser acceptance remain deployment checks.
