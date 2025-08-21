#!/usr/bin/env bash
# setup.sh — Replit-friendly liboqs + liboqs-python bootstrap (no Docker/root)
set -euo pipefail

# --- Fix Replit pip defaulting to --user in venv ---
export PIP_USER=0
export PYTHONNOUSERSITE=1
pip config unset global.user  >/dev/null 2>&1 || true
pip config --user unset global.user >/dev/null 2>&1 || true
unset PYTHONUSERBASE

# ---- Config ----
LIBOQS_PY_VER="0.12.0"
PREFIX="${OQS_INSTALL_PATH:-$HOME/.local}"          # where liboqs will be installed
BUILD_DIR="${HOME}/.cache/liboqs-build"             # persistent build cache across runs
VENV_DIR="${VENV_DIR:-.venv}"                       # python venv location
NUM_JOBS="${NUM_JOBS:-$(command -v nproc >/dev/null && nproc || echo 2)}"

# ---- Helpers ----
need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing '$1' — add it to [nix].packages."; exit 1; }; }
msg() { printf "\n\033[1;36m[setup]\033[0m %s\n" "$*"; }

# ---- Pre-flight ----
for bin in git cmake gcc python3 pip; do need "$bin"; done
GEN="Ninja"; if ! command -v ninja >/dev/null 2>&1; then GEN="Unix Makefiles"; fi

mkdir -p "$PREFIX" "$BUILD_DIR"

# ---- Python venv ----
if [ ! -d "$VENV_DIR" ]; then
  msg "creating venv in $VENV_DIR"
  python3 -m venv "$VENV_DIR"
fi
# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"

# ensure pip installs into venv (not --user)
export PIP_USER=0
export PYTHONNOUSERSITE=1
pip config unset global.user  >/dev/null 2>&1 || true
pip config --user unset global.user >/dev/null 2>&1 || true
unset PYTHONUSERBASE

python -m pip install --upgrade --no-cache-dir pip setuptools wheel

# ---- liboqs (C library) ----
LIB_SO_LINUX="$PREFIX/lib/liboqs.so"
LIB_DYLIB_MAC="$PREFIX/lib/liboqs.dylib"
if [ -f "$LIB_SO_LINUX" ] || [ -f "$LIB_DYLIB_MAC" ]; then
  msg "liboqs already installed at $PREFIX/lib"
else
  msg "building liboqs into $PREFIX (generator: $GEN)"
  rm -rf "${BUILD_DIR:?}/liboqs-src" "${BUILD_DIR:?}/build"
  git clone --depth=1 --recurse-submodules https://github.com/open-quantum-safe/liboqs "${BUILD_DIR}/liboqs-src"
  cmake -S "${BUILD_DIR}/liboqs-src" -B "${BUILD_DIR}/build" \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_USE_OPENSSL=OFF \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -G "$GEN"
  cmake --build "${BUILD_DIR}/build" --parallel "$NUM_JOBS"
  cmake --install "${BUILD_DIR}/build"
fi

# ---- Runtime env for dynamic linker ----
export OQS_INSTALL_PATH="$PREFIX"
case "$(uname -s)" in
  Darwin) export DYLD_LIBRARY_PATH="$PREFIX/lib:${DYLD_LIBRARY_PATH:-}";;
  *)      export LD_LIBRARY_PATH="$PREFIX/lib:${LD_LIBRARY_PATH:-}";;
esac

# Persist env for future shells
cat > .env.oqs <<EOF
export OQS_INSTALL_PATH="$PREFIX"
export LD_LIBRARY_PATH="$PREFIX/lib:\$LD_LIBRARY_PATH"
export DYLD_LIBRARY_PATH="$PREFIX/lib:\$DYLD_LIBRARY_PATH"
EOF

# ---- Python deps (version-locked, including OQS from GitHub) ----
if [ -f requirements.txt ]; then
  msg "pip installing requirements.txt"
  pip install --no-cache-dir -r requirements.txt
else
  msg "installing liboqs-python ${LIBOQS_PY_VER} (no requirements.txt found)"
  pip install --no-cache-dir "git+https://github.com/open-quantum-safe/liboqs-python@${LIBOQS_PY_VER}"
fi

# ---- Smoke test ----
msg "running smoke test"
python - <<'PY'
import os, oqs
print("OQS_INSTALL_PATH =", os.environ.get("OQS_INSTALL_PATH"))
print("Enabled KEMs:", len(oqs.get_enabled_kem_mechanisms()))
print("OK")
PY

msg "done. To use in a new shell: source .venv/bin/activate && source .env.oqs"
