#!/usr/bin/env bash
# setup.sh — Replit-friendly liboqs + liboqs-python + pinned deps (no Docker/root, no venv)
set -euo pipefail

# ---- Helpers ----
need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing '$1' — add it to [nix].packages."; exit 1; }; }
msg()  { printf "\n\033[1;36m[setup]\033[0m %s\n" "$*"; }

# ---- Pre-flight ----
for bin in git cmake gcc python3 pip; do need "$bin"; done
GEN="Ninja"; command -v ninja >/dev/null 2>&1 || GEN="Unix Makefiles"

# ---- Config ----
LIBOQS_PY_VER="${LIBOQS_PY_VER:-0.12.0}"
PREFIX="${OQS_INSTALL_PATH:-$HOME/.local}"        # liboqs (C) install prefix
BUILD_DIR="${HOME}/.cache/liboqs-build"           # persistent build cache
PY_TARGET="${PY_TARGET:-$PWD/.python_packages}"   # where Python deps will be installed
NUM_JOBS="${NUM_JOBS:-$(command -v nproc >/dev/null && nproc || echo 2)}"

mkdir -p "$PREFIX" "$BUILD_DIR" "$PY_TARGET"

# ---- Keep pip away from system site-packages (PEP 668-safe) ----
export PIP_DISABLE_PIP_VERSION_CHECK=1
export PIP_USER=0
export PYTHONNOUSERSITE=1
unset PYTHONUSERBASE
pip config unset global.user  >/dev/null 2>&1 || true
pip config --user unset global.user >/dev/null 2>&1 || true

# Expose local target (append so stdlib wins; avoids pathlib shadowing)
export PYTHONPATH="${PYTHONPATH:+$PYTHONPATH:}$PY_TARGET"

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

# ---- Runtime env for dynamic linker & build tooling ----
export OQS_INSTALL_PATH="$PREFIX"
case "$(uname -s)" in
  Darwin) export DYLD_LIBRARY_PATH="$PREFIX/lib:${DYLD_LIBRARY_PATH:-}";;
  *)      export LD_LIBRARY_PATH="$PREFIX/lib:${LD_LIBRARY_PATH:-}";;
esac
export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
export CFLAGS="-I$PREFIX/include ${CFLAGS:-}"
export LDFLAGS="-L$PREFIX/lib ${LDFLAGS:-}"

# Persist env for future shells
cat > .env.oqs <<EOF
# Load me before running Python:  source .env.oqs
export OQS_INSTALL_PATH="$PREFIX"
export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig:\$PKG_CONFIG_PATH"
export CFLAGS="-I$PREFIX/include \${CFLAGS:-}"
export LDFLAGS="-L$PREFIX/lib \${LDFLAGS:-}"
export LD_LIBRARY_PATH="$PREFIX/lib:\$LD_LIBRARY_PATH"
export DYLD_LIBRARY_PATH="$PREFIX/lib:\$DYLD_LIBRARY_PATH"
# Append .python_packages so stdlib wins (avoids pathlib shadowing)
export PYTHONPATH="\${PYTHONPATH:+\$PYTHONPATH:}$PY_TARGET"
EOF

# ---- Bootstrap build wheels into target (wheel/cffi/etc.) ----
msg "bootstrap Python build tooling into $PY_TARGET"
python3 -m pip install --no-cache-dir --target "$PY_TARGET" \
  "setuptools>=65" "wheel>=0.41" "cffi>=1.15" "packaging>=23" >/dev/null

# ---- Your pinned packages (installed here, not via requirements.txt) ----
# IMPORTANT: do NOT install any package named 'pathlib' (breaks Python 3.12 stdlib)
msg "installing pinned Python packages into $PY_TARGET"
python3 - <<'PY'
import os, subprocess, sys
target = os.environ.get("PY_TARGET", ".python_packages")
pkgs = [
  "flask[async]==3.1.2",
  "cryptography==45.0.6",
  "httpx[http2]==0.28.1",
  "pennylane==0.42.3",
  "psutil==7.0.0",
  "waitress==3.0.2",
  "bleach==6.2.0",
  "argon2-cffi==25.1.0",
  "Flask-WTF==1.2.2",
  "markdown2==2.5.4",
  "WTForms==3.2.1",
  "geonamescache==2.0.0",
  "backoff==2.2.1",
  "coinbase-advanced-py==1.8.2",
  "coinbase==2.1.0",
  "argon2==0.1.10",
  "numpy==2.3.2",
  "itsdangerous==2.2.0",
  "zstandard==0.24.0",
]
# Filter any accidental 'pathlib' entry
pkgs = [p for p in pkgs if p.split("==")[0].strip().lower() != "pathlib"]
if pkgs:
    cmd = [sys.executable, "-m", "pip", "install", "--no-cache-dir", "--target", target, *pkgs]
    print("[setup] running:", " ".join(cmd))
    subprocess.check_call(cmd)
else:
    print("[setup] nothing to install")
PY

# ---- liboqs-python (Python wrapper) ----
if python3 -c "import oqs" >/dev/null 2>&1; then
  msg "oqs already importable, skipping liboqs-python install"
else
  msg "installing liboqs-python ${LIBOQS_PY_VER} into $PY_TARGET"
  if ! python3 -m pip install --no-cache-dir --target "$PY_TARGET" \
      "git+https://github.com/open-quantum-safe/liboqs-python@${LIBOQS_PY_VER}"; then
    # Fallback to PyPI (if available)
    python3 -m pip install --no-cache-dir --target "$PY_TARGET" "liboqs-python==${LIBOQS_PY_VER}" || true
  fi
fi

# ---- Smoke tests ----
msg "running smoke tests"
python3 - <<'PY'
import os, sys
print("Python:", sys.version.split()[0])
print("PYTHONPATH endswith .python_packages:", sys.path[-1].endswith(".python_packages"))
print("OQS_INSTALL_PATH =", os.environ.get("OQS_INSTALL_PATH"))
# Core deps
import flask, httpx, psutil, numpy
print("Flask:", flask.__version__, "| httpx:", httpx.__version__, "| numpy:", numpy.__version__)
# OQS
try:
    import oqs
    print("Enabled KEMs:", len(oqs.get_enabled_kem_mechanisms()))
    print("OK")
except Exception as e:
    print("Import oqs FAILED:", e)
    raise
PY

msg "done. Run with:  source .env.oqs && python3 main.py"
