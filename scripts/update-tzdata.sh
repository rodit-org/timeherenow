#!/usr/bin/env bash
set -euo pipefail

# Update the IANA Time Zone Database (tzdb) by upgrading @vvo/tzdb
# Usage: scripts/update-tzdata.sh [@vvo/tzdb-version]
# Examples:
#   scripts/update-tzdata.sh             # install latest
#   scripts/update-tzdata.sh 6.186.0     # install specific version

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TZDB_VERSION="${1:-latest}"

echo "[tzdb] Project root: $ROOT_DIR"
echo "[tzdb] Requested @vvo/tzdb version: $TZDB_VERSION"
echo "[tzdb] Node: $(node -v)"
echo "[tzdb] npm:  $(npm -v)"

CURRENT_TZDB_PKG=$(node -e "try{console.log(require('@vvo/tzdb/package.json').version)}catch(e){console.log('not installed')}")
CURRENT_TZ_COUNT=$(node -e "try{const {getTimeZones}=require('@vvo/tzdb');console.log(getTimeZones().length)}catch(e){console.log('not installed')}")

echo "[tzdb] Current @vvo/tzdb: $CURRENT_TZDB_PKG"
echo "[tzdb] Current zones count: $CURRENT_TZ_COUNT"

echo "[tzdb] Installing @vvo/tzdb@${TZDB_VERSION} ..."
npm install "@vvo/tzdb@${TZDB_VERSION}" --save

echo "[tzdb] Reading updated versions ..."
UPDATED_TZDB_PKG=$(node -e "console.log(require('@vvo/tzdb/package.json').version)")
UPDATED_TZ_COUNT=$(node -e "const {getTimeZones}=require('@vvo/tzdb');console.log(getTimeZones().length)")

echo "[tzdb] Updated @vvo/tzdb: $UPDATED_TZDB_PKG"
echo "[tzdb] Updated zones count: $UPDATED_TZ_COUNT"

echo "[tzdb] Done. Commit package.json and package-lock.json to lock the update."
