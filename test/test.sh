#!/usr/bin/env bash
set -euo pipefail

BASE_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

julia +1.12 --project="$BASE_PATH/.." -e "import Pkg; Pkg.test(test_args=ARGS)" -- "$@"
