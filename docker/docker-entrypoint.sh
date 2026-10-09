#!/bin/sh
set -eu

if [ -z "${MCP_DSH_ROOT:-}" ]; then
  echo "[dsh-passwords] MCP_DSH_ROOT is required in gate-only Docker mode." >&2
  echo "[dsh-passwords] Mount the dsh installation directory and set MCP_DSH_ROOT to that mount path." >&2
  exit 1
fi
if [ ! -d "$MCP_DSH_ROOT" ]; then
  echo "[dsh-passwords] dsh directory not found at $MCP_DSH_ROOT; refusing to start without the remote-settings patch." >&2
  exit 1
fi

# Validate the gate-only runtime before docker-init writes persistent state.
node /opt/dsh-passwords/dist/cli.js docker-init
if ! node /opt/dsh-passwords/dist/cli.js patch; then
  echo "[dsh-passwords] dsh patch failed; refusing to start. Check the mounted dsh version and MCP_DSH_ROOT." >&2
  exit 1
fi
echo "[dsh-passwords] dsh patch applied. Restart the dsh web service/container now to load it."
exec "$@"
