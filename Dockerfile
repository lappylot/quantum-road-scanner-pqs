 
FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OQS_INSTALL_PATH=/usr/local

# --- system deps for liboqs & building wheels ---
RUN apt-get update && apt-get install -y --no-install-recommends \
    git cmake ninja-build build-essential pkg-config ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# --- build & install liboqs (shared, pinned to 0.14.0) ---
RUN git clone --branch "0.14.0" --depth=1 --recurse-submodules https://github.com/open-quantum-safe/liboqs /tmp/liboqs \
 && cmake -S /tmp/liboqs -B /tmp/liboqs/build \
      -DCMAKE_INSTALL_PREFIX=/usr/local \
      -DBUILD_SHARED_LIBS=ON \
      -DOQS_USE_OPENSSL=OFF \
      -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
      -G Ninja \
 && cmake --build /tmp/liboqs/build --parallel \
 && cmake --install /tmp/liboqs/build \
 && rm -rf /tmp/liboqs

# help the dynamic linker find liboqs
RUN printf "/usr/local/lib\n" > /etc/ld.so.conf.d/usr-local-lib.conf && ldconfig
ENV LD_LIBRARY_PATH=/usr/local/lib:${LD_LIBRARY_PATH}

# --- app setup ---
WORKDIR /app

# install Python deps (make sure liboqs-python is NOT in requirements.txt)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# install the oqs Python wrapper after liboqs exists (pinned to 0.12.0)
RUN pip install --no-cache-dir "git+https://github.com/open-quantum-safe/liboqs-python@0.12.0"

# copy the rest
COPY . .

# create unprivileged user + lock down app dirs (no secrets written here)
RUN useradd -ms /bin/bash appuser \
 && mkdir -p /app/static \
 && chmod 755 /app/static \
 && chown -R appuser:appuser /app

# --- generate per-build secrets that will *break* old DB decryption ---
# Regenerated on every docker build, written to /etc/qrs.env
RUN python - <<'PY'
import secrets, base64, pwd, grp, pathlib, os
def b64(n): return base64.b64encode(secrets.token_bytes(n)).decode()
env = {
  # app secret at import time
  "INVITE_CODE_SECRET_KEY": secrets.token_hex(32),
  # KDF inputs — changing these makes previous DB ciphertexts undecryptable
  "ENCRYPTION_PASSPHRASE": base64.urlsafe_b64encode(secrets.token_bytes(48)).decode().rstrip("="),
  "QRS_SALT_B64": b64(32),
  # behavior flags
  "STRICT_PQ2_ONLY": "1",
  "QRS_ENABLE_SEALED": "0",
  "QRS_ROTATE_SESSION_KEY": "1",
}
p = pathlib.Path("/etc/qrs.env")
with p.open("w") as f:
    for k, v in env.items():
        f.write(f'export {k}="{v}"\n')
uid = pwd.getpwnam("appuser").pw_uid
gid = grp.getgrnam("appuser").gr_gid
os.chown("/etc/qrs.env", uid, gid)
os.chmod("/etc/qrs.env", 0o600)
PY

# --- runtime entrypoint: load per-build KDF, force fresh keypairs each start ---
COPY --chown=appuser:appuser <<'SH' /app/entrypoint.sh
#!/usr/bin/env sh
set -euo pipefail

# Load per-build secrets (KDF inputs etc.)
if [ -f /etc/qrs.env ]; then
  # shellcheck disable=SC1091
  . /etc/qrs.env
fi

# Strong defaults if overridden
export STRICT_PQ2_ONLY="${STRICT_PQ2_ONLY:-1}"
export QRS_ENABLE_SEALED="${QRS_ENABLE_SEALED:-0}"
export QRS_ROTATE_SESSION_KEY="${QRS_ROTATE_SESSION_KEY:-1}"

# Force *new* keypairs every container start (does not affect KDF).
unset QRS_X25519_PUB_B64 QRS_X25519_PRIV_ENC_B64 \
      QRS_PQ_KEM_ALG QRS_PQ_PUB_B64 QRS_PQ_PRIV_ENC_B64 \
      QRS_SIG_ALG QRS_SIG_PUB_B64 QRS_SIG_PRIV_ENC_B64 \
      QRS_SEALED_B64

# Hard fail if KDF inputs missing (safety)
: "${ENCRYPTION_PASSPHRASE:?missing}"
: "${QRS_SALT_B64:?missing}"
: "${INVITE_CODE_SECRET_KEY:?missing}"

exec "$@"
SH
RUN chmod +x /app/entrypoint.sh

USER appuser
EXPOSE 3000

ENTRYPOINT ["/app/entrypoint.sh"]
# Start the Flask application using waitress
CMD ["waitress-serve", "--host=0.0.0.0", "--port=3000", "--threads=4", "main:app"]
