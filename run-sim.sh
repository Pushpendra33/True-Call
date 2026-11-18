#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
source "$HOME/.cargo/env"

echo "=========================================================="
echo "    TRUECALL: PASSPORT PRIME DEEPFAKE-PROOF SIMULATOR     "
echo "=========================================================="

cd "$DIR/truecall-core"
cargo run --bin truecall-sim "$@"

