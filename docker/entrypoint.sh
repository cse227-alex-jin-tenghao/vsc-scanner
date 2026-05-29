#!/usr/bin/env bash
# Entrypoint for the vsc-scanner pod.
#
# The host-side run.sh has already:
#   - cloned/updated the repo into $HOME/vsc-scanner (the docker branch)
#   - written $HOME/vsc-scanner/pw.txt (no trailing newline)
#   - placed $HOME/marketplace_extensions.json
# We just need to point run_node.py at those files and exec it.
set -euo pipefail

REPO_DIR="${VSC_REPO_DIR:-$HOME/vsc-scanner}"
export VSC_PW_PATH="${VSC_PW_PATH:-$REPO_DIR/pw.txt}"
export VSC_EXTENSIONS_JSON="${VSC_EXTENSIONS_JSON:-$HOME/marketplace_extensions.json}"
export VSC_LOG_PATH="${VSC_LOG_PATH:-$REPO_DIR/log.txt}"

cd "$REPO_DIR"
exec python3 scripts/run_node.py "$@"
