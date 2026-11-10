#!/bin/sh
# Lightweight local checks only: no VMs, real media or image downloads.
set -eu
cd -- "$(dirname -- "$0")"
python3 -m unittest discover -s tests
node --check static/app.js
node --check static/ui.js
node --check preview.mjs
sh -n image/setup.sh
sh -n image/keys.sh
bash -n image/info.sh
