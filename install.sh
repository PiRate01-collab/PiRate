#!/bin/sh
# PiRate beta installation entry point. No AP or upstream activation at install.
set -eu
PIRATE_INSTALL_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$PIRATE_INSTALL_DIR/install-pi.sh" "$@"
