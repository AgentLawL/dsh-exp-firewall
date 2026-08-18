#!/bin/sh
set -eu

python_bin="${EXP_FIREWALL_PYTHON:-python3}"
"$python_bin" scripts/render-hero-gif.py assets/evidence-recovery.gif
