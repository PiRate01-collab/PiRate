#!/bin/sh
set -eu
PIRATE_SOURCE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 -B "$PIRATE_SOURCE_DIR/tools/install_pi.py" "$@"
