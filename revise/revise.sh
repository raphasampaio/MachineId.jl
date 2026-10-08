#!/usr/bin/env bash
set -euo pipefail

BASE_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

julia --project="$BASE_PATH" --interactive --load="$BASE_PATH/revise.jl"
