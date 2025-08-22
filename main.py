from __future__ import annotations 
import logging
import httpx
import sqlite3
import psutil
from flask import (Flask, render_template_string, request, redirect, url_for,
                   session, jsonify, flash)
from flask_wtf import FlaskForm, CSRFProtect
from flask_wtf.csrf import generate_csrf
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from waitress import serve
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from argon2.low_level import Type
from datetime import timedelta, datetime
from markdown2 import markdown
import bleach
import geonamescache
import random
import re
import base64
import math
import threading
import time
import hmac
import hashlib
import secrets
from typing import Tuple, Callable, Dict, List, Union, Any, Optional, Mapping, cast
import uuid
import asyncio
import sys
import pennylane as qml
import numpy as np
from pathlib import Path
import os
import json
import string
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA3_512
from argon2.low_level import hash_secret_raw, Type as ArgonType
from numpy.random import Generator, PCG64DXSM
import itertools
import colorsys
from dataclasses import dataclass
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from collections import deque
from flask.sessions import SecureCookieSessionInterface
from flask.json.tag  import TaggedJSONSerializer
from itsdangerous import URLSafeTimedSerializer, BadSignature, BadTimeSignature
import zlib as _zlib 
try:
    import zstandard as zstd  
    _HAS_ZSTD = True
except Exception:
    zstd = None  
    _HAS_ZSTD = False
    
try:
    from typing import TypedDict
except ImportError:
    from typing_extensions import TypedDict

try:
    import oqs as _oqs  
    oqs = cast(Any, _oqs)  
except Exception:
    oqs = cast(Any, None)

class SealedCache(TypedDict, total=False):
    x25519_priv_raw: bytes
    pq_priv_raw: Optional[bytes]
    sig_priv_raw: bytes
    kem_alg: str
    sig_alg: str
    
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
STRICT_PQ2_ONLY = True
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)

formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)


logger.addHandler(console_handler)

app = Flask(__name__)

SECRET_KEY = os.getenv("INVITE_CODE_SECRET_KEY")
if not SECRET_KEY:
    raise ValueError(
        "INVITE_CODE_SECRET_KEY environment variable is not defined!")

if isinstance(SECRET_KEY, str):
    SECRET_KEY = SECRET_KEY.encode("utf-8")

_entropy_state = {
    "wheel":
    itertools.cycle([
        b'\xff\x20\x33', b'\x22\xaa\xff', b'\x00\xee\x44', b'\xf4\x44\x00',
        b'\x11\x99\xff', b'\xad\x11\xec'
    ]),
    "rng":
    np.random.Generator(
        np.random.PCG64DXSM(
            [int.from_bytes(os.urandom(4), 'big') for _ in range(8)]))
}

ADMIN_USERNAME = os.getenv("admin_username")
ADMIN_PASS = os.getenv("admin_pass")

if not ADMIN_USERNAME or not ADMIN_PASS:
    raise ValueError(
        "admin_username and/or admin_pass environment variables are not defined! "
        "Set them in your environment before starting the app.")

if 'parse_safe_float' not in globals():
    def parse_safe_float(val) -> float:

        s = str(val).strip()
        bad = {'nan', '+nan', '-nan', 'inf', '+inf', '-inf', 'infinity', '+infinity', '-infinity'}
        if s.lower() in bad:
            raise ValueError("Non-finite float not allowed")
        f = float(s)
        if not math.isfinite(f):
            raise ValueError("Non-finite float not allowed")
        return f

# === ENV names for key-only-in-env mode ===
ENV_SALT_B64              = "QRS_SALT_B64"             # base64 salt for KDF (Scrypt/Argon2)
ENV_X25519_PUB_B64        = "QRS_X25519_PUB_B64"
ENV_X25519_PRIV_ENC_B64   = "QRS_X25519_PRIV_ENC_B64"  # AESGCM(nonce|ct) b64
ENV_PQ_KEM_ALG            = "QRS_PQ_KEM_ALG"           # e.g. "ML-KEM-768"
ENV_PQ_PUB_B64            = "QRS_PQ_PUB_B64"
ENV_PQ_PRIV_ENC_B64       = "QRS_PQ_PRIV_ENC_B64"      # AESGCM(nonce|ct) b64
ENV_SIG_ALG               = "QRS_SIG_ALG"              # "ML-DSA-87"/"Dilithium5"/"Ed25519"
ENV_SIG_PUB_B64           = "QRS_SIG_PUB_B64"
ENV_SIG_PRIV_ENC_B64      = "QRS_SIG_PRIV_ENC_B64"     # AESGCM(nonce|ct) b64
ENV_SEALED_B64            = "QRS_SEALED_B64"           # sealed store JSON (env) b64

# Small b64 helpers (env <-> bytes)

def _b64set(name: str, raw: bytes) -> None:
    os.environ[name] = base64.b64encode(raw).decode("utf-8")

def _b64get(name: str, required: bool = False) -> Optional[bytes]:
    s = os.getenv(name)
    if not s:
        if required:
            raise ValueError(f"Missing required env var: {name}")
        return None
    return base64.b64decode(s.encode("utf-8"))

def _derive_kek(passphrase: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        passphrase.encode("utf-8"),
        salt,
        3,                      # time_cost
        512 * 1024,             # memory_cost (KiB)
        max(2, (os.cpu_count() or 2)//2),  # parallelism
        32,
        ArgonType.ID
    )

def _enc_with_label(kek: bytes, label: bytes, raw: bytes) -> bytes:
    n = secrets.token_bytes(12)
    ct = AESGCM(kek).encrypt(n, raw, label)
    return n + ct

def _detect_oqs_kem() -> Optional[str]:
    if oqs is None: return None
    for n in ("ML-KEM-768","Kyber768","FIPS204-ML-KEM-768"):
        try:
            oqs.KeyEncapsulation(n)
            return n
        except Exception:
            continue
    return None

def _detect_oqs_sig() -> Optional[str]:
    if oqs is None: return None
    for n in ("ML-DSA-87","ML-DSA-65","Dilithium5","Dilithium3"):
        try:
            oqs.Signature(n)
            return n
        except Exception:
            continue
    return None

def _gen_passphrase() -> str:
    return base64.urlsafe_b64encode(os.urandom(48)).decode().rstrip("=")

def bootstrap_env_keys(strict_pq2: bool = True, echo_exports: bool = False) -> None:
    """
    Generates any missing secrets directly into os.environ (no files).
    Safe to call multiple times. If echo_exports=True, prints export lines.
    """
    exports: list[tuple[str,str]] = []

    # 1) Ensure passphrase & salt
    if not os.getenv("ENCRYPTION_PASSPHRASE"):
        pw = _gen_passphrase()
        os.environ["ENCRYPTION_PASSPHRASE"] = pw
        exports.append(("ENCRYPTION_PASSPHRASE", pw))
        logger.warning("ENCRYPTION_PASSPHRASE was missing — generated for this process.")
    passphrase = os.environ["ENCRYPTION_PASSPHRASE"]

    salt = _b64get(ENV_SALT_B64)
    if salt is None:
        salt = os.urandom(32)
        _b64set(ENV_SALT_B64, salt)
        exports.append((ENV_SALT_B64, base64.b64encode(salt).decode()))
        logger.info("Generated KDF salt to env.")
    kek = _derive_kek(passphrase, salt)

    # 2) x25519
    if not (os.getenv(ENV_X25519_PUB_B64) and os.getenv(ENV_X25519_PRIV_ENC_B64)):
        x_priv = x25519.X25519PrivateKey.generate()
        x_pub  = x_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        x_raw  = x_priv.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        )
        x_enc  = _enc_with_label(kek, b"x25519", x_raw)
        _b64set(ENV_X25519_PUB_B64, x_pub)
        _b64set(ENV_X25519_PRIV_ENC_B64, x_enc)
        exports.append((ENV_X25519_PUB_B64, base64.b64encode(x_pub).decode()))
        exports.append((ENV_X25519_PRIV_ENC_B64, base64.b64encode(x_enc).decode()))
        logger.info("Generated x25519 keypair to env.")

    # 3) PQ KEM (strict mode requires it)
    need_pq = strict_pq2 or os.getenv(ENV_PQ_KEM_ALG) or oqs is not None
    if need_pq:
        if oqs is None and strict_pq2:
            raise RuntimeError("STRICT_PQ2_ONLY=1 but liboqs is unavailable.")
        if not (os.getenv(ENV_PQ_KEM_ALG) and os.getenv(ENV_PQ_PUB_B64) and os.getenv(ENV_PQ_PRIV_ENC_B64)):
            alg = os.getenv(ENV_PQ_KEM_ALG) or _detect_oqs_kem()
            if not alg and strict_pq2:
                raise RuntimeError("Strict PQ2 mode: ML-KEM not available.")
            if alg and oqs is not None:
                with oqs.KeyEncapsulation(alg) as kem:
                    pq_pub = kem.generate_keypair()
                    pq_sk  = kem.export_secret_key()
                pq_enc = _enc_with_label(kek, b"pqkem", pq_sk)
                os.environ[ENV_PQ_KEM_ALG] = alg
                _b64set(ENV_PQ_PUB_B64, pq_pub)
                _b64set(ENV_PQ_PRIV_ENC_B64, pq_enc)
                exports.append((ENV_PQ_KEM_ALG, alg))
                exports.append((ENV_PQ_PUB_B64, base64.b64encode(pq_pub).decode()))
                exports.append((ENV_PQ_PRIV_ENC_B64, base64.b64encode(pq_enc).decode()))
                logger.info("Generated PQ KEM keypair (%s) to env.", alg)

    # 4) Signature (PQ preferred; Ed25519 fallback if not strict)
    if not (os.getenv(ENV_SIG_ALG) and os.getenv(ENV_SIG_PUB_B64) and os.getenv(ENV_SIG_PRIV_ENC_B64)):
        pq_sig = _detect_oqs_sig()
        if pq_sig:
            with oqs.Signature(pq_sig) as s:
                sig_pub = s.generate_keypair()
                sig_sk  = s.export_secret_key()
            sig_enc = _enc_with_label(kek, b"pqsig", sig_sk)
            os.environ[ENV_SIG_ALG] = pq_sig
            _b64set(ENV_SIG_PUB_B64, sig_pub)
            _b64set(ENV_SIG_PRIV_ENC_B64, sig_enc)
            exports.append((ENV_SIG_ALG, pq_sig))
            exports.append((ENV_SIG_PUB_B64, base64.b64encode(sig_pub).decode()))
            exports.append((ENV_SIG_PRIV_ENC_B64, base64.b64encode(sig_enc).decode()))
            logger.info("Generated PQ signature keypair (%s) to env.", pq_sig)
        else:
            if strict_pq2:
                raise RuntimeError("Strict PQ2 mode: ML-DSA required but oqs unavailable.")
            kp = ed25519.Ed25519PrivateKey.generate()
            pub = kp.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            raw = kp.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
            )
            enc = _enc_with_label(kek, b"ed25519", raw)
            os.environ[ENV_SIG_ALG] = "Ed25519"
            _b64set(ENV_SIG_PUB_B64, pub)
            _b64set(ENV_SIG_PRIV_ENC_B64, enc)
            exports.append((ENV_SIG_ALG, "Ed25519"))
            exports.append((ENV_SIG_PUB_B64, base64.b64encode(pub).decode()))
            exports.append((ENV_SIG_PRIV_ENC_B64, base64.b64encode(enc).decode()))
            logger.info("Generated Ed25519 signature keypair to env (fallback).")

    if echo_exports:
        print("# --- QRS bootstrap exports (persist in your secret store) ---")
        for k, v in exports:
            print(f"export {k}='{v}'")
        print("# ------------------------------------------------------------")

if 'IDENTIFIER_RE' not in globals():
    IDENTIFIER_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')

if 'quote_ident' not in globals():
    def quote_ident(name: str) -> str:
        if not isinstance(name, str) or not IDENTIFIER_RE.match(name):
            raise ValueError(f"Invalid SQL identifier: {name!r}")
        return '"' + name.replace('"', '""') + '"'

if '_is_safe_condition_sql' not in globals():
    def _is_safe_condition_sql(cond: str) -> bool:
       
        return bool(re.fullmatch(r"[A-Za-z0-9_\s\.\=\>\<\!\?\(\),]*", cond or ""))

def _chaotic_three_fry_mix(buf: bytes) -> bytes:
    import struct
    words = list(
        struct.unpack('>4Q',
                      hashlib.blake2b(buf, digest_size=32).digest()))
    for i in range(2):
        words[0] = (words[0] + words[1]) & 0xffffffffffffffff
        words[1] = ((words[1] << 13) | (words[1] >> 51)) & 0xffffffffffffffff
        words[1] ^= words[0]
        words[2] = (words[2] + words[3]) & 0xffffffffffffffff
        words[3] = ((words[3] << 16) | (words[3] >> 48)) & 0xffffffffffffffff
        words[3] ^= words[2]
    return struct.pack('>4Q', *words)

def validate_password_strength(password):
    if len(password) < 8:
        return False

    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[@$!%*?&]", password):
        return False
    return True
    
def generate_very_strong_secret_key():

    global _entropy_state

    E = [
        os.urandom(64),
        secrets.token_bytes(48),
        uuid.uuid4().bytes,
        f"{psutil.cpu_percent()}|{psutil.virtual_memory().percent}".encode(),
        str((time.time_ns(), time.perf_counter_ns())).encode(),
        f"{os.getpid()}:{os.getppid()}:{threading.get_ident()}".encode(),
        next(_entropy_state["wheel"]),
    ]

    base = hashlib.blake2b(b"||".join(E), digest_size=64).digest()
    chaotic = _chaotic_three_fry_mix(base)

    rounds = int(_entropy_state["rng"].integers(1, 5))
    for _ in range(4 + rounds):
        chaotic = hashlib.shake_256(chaotic).digest(64)
        chaotic = _chaotic_three_fry_mix(chaotic)

    raw = hash_secret_raw(chaotic,
                          os.urandom(16),
                          time_cost=4,
                          memory_cost=256000,
                          parallelism=2,
                          hash_len=48,
                          type=ArgonType.ID)

    hkdf = HKDF(algorithm=SHA3_512(),
                length=32,
                salt=os.urandom(32),
                info=b"QRS|rotating-session-key|v4",
                backend=default_backend())
    final_key = hkdf.derive(raw)

    lhs = int.from_bytes(final_key[:16], 'big')
    rhs = int(_entropy_state["rng"].integers(0, 1 << 63))
    seed64 = (lhs ^ rhs) & ((1 << 64) - 1)

    seed_list = [(seed64 >> 32) & 0xffffffff, seed64 & 0xffffffff]
    _entropy_state["rng"] = Generator(PCG64DXSM(seed_list))

    return final_key


def get_very_complex_random_interval():

    c = psutil.cpu_percent()
    r = psutil.virtual_memory().percent
    cw = int.from_bytes(next(_entropy_state["wheel"]), 'big')
    rng = _entropy_state["rng"].integers(7, 15)
    base = (9 * 60) + secrets.randbelow(51 * 60)
    jitter = int((c * r * 13 + cw * 7 + rng) % 311)
    return base + jitter

RECENT_KEYS = deque(maxlen=5) 

def _get_all_secret_keys():

    current = getattr(app, "secret_key", None)
    others = [k for k in list(RECENT_KEYS) if k is not current and k is not None]
    return [current] + others if current else others

class MultiKeySessionInterface(SecureCookieSessionInterface):
    serializer = TaggedJSONSerializer()

    def _make_serializer(self, secret_key):
        if not secret_key:
            return None
        signer_kwargs = dict(key_derivation=self.key_derivation,
                             digest_method=self.digest_method)
        return URLSafeTimedSerializer(secret_key, salt=self.salt,
                                      serializer=self.serializer,
                                      signer_kwargs=signer_kwargs)

    def open_session(self, app, request):
        cookie_name = self.get_cookie_name(app)  
        s = request.cookies.get(cookie_name)
        if not s:
            return self.session_class()

        max_age = int(app.permanent_session_lifetime.total_seconds())
        for key in _get_all_secret_keys():
            ser = self._make_serializer(key)
            if not ser:
                continue
            try:
                data = ser.loads(s, max_age=max_age)
                return self.session_class(data)
            except (BadTimeSignature, BadSignature, Exception):
                continue
        return self.session_class()

    def save_session(self, app, session, response):
        key = getattr(app, "secret_key", None)
        ser = self._make_serializer(key)
        if not ser:
            return

        cookie_name = self.get_cookie_name(app) 
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)

        if not session:
            if session.modified:
                response.delete_cookie(
                    cookie_name,
                    domain=domain,
                    path=path,
                    secure=self.get_cookie_secure(app),
                    samesite=self.get_cookie_samesite(app),
                )
            return

        httponly = self.get_cookie_httponly(app)
        secure = self.get_cookie_secure(app)
        samesite = self.get_cookie_samesite(app)
        expires = self.get_expiration_time(app, session)

        val = ser.dumps(dict(session))
        response.set_cookie(
            cookie_name,           
            val,
            expires=expires,
            httponly=httponly,
            domain=domain,
            path=path,
            secure=secure,
            samesite=samesite,
        )

        
app.session_interface = MultiKeySessionInterface()

def rotate_secret_key():
    lock = threading.Lock()
    while True:
        with lock:
            sk = generate_very_strong_secret_key()
       
            prev = getattr(app, "secret_key", None)
            if prev:
                RECENT_KEYS.appendleft(prev)
            app.secret_key = sk
            fp = base64.b16encode(sk[:6]).decode()
            logger.info(f"Secret key rotated (fp={fp})")
        time.sleep(get_very_complex_random_interval())

BASE_DIR = Path(__file__).parent.resolve()

key_rotation_thread = threading.Thread(target=rotate_secret_key, daemon=True)
key_rotation_thread.start()

RATE_LIMIT_COUNT = 13
RATE_LIMIT_WINDOW = timedelta(minutes=15)

config_lock = threading.Lock()
DB_FILE = BASE_DIR / 'secure_data.db'
EXPIRATION_HOURS = 65

app.config.update(SESSION_COOKIE_SECURE=True,
                  SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE='Strict',
                  WTF_CSRF_TIME_LIMIT=3600,
                  SECRET_KEY=SECRET_KEY)

csrf = CSRFProtect(app)

@app.after_request
def apply_csp(response):
    csp_policy = ("default-src 'self'; "
                  "script-src 'self' 'unsafe-inline'; "
                  "style-src 'self' 'unsafe-inline'; "
                  "font-src 'self' data:; "
                  "img-src 'self' data:; "
                  "object-src 'none'; "
                  "base-uri 'self'; ")
    response.headers['Content-Security-Policy'] = csp_policy
    return response

class KeyManager:
    encryption_key: Optional[bytes]
    passphrase_env_var: str
    backend: Any
    _pq_alg_name: Optional[str] = None
    x25519_pub: bytes = b""
    _x25519_priv_enc: bytes = b""
    pq_pub: Optional[bytes] = None
    _pq_priv_enc: Optional[bytes] = None
    sig_alg_name: Optional[str] = None
    sig_pub: Optional[bytes] = None
    _sig_priv_enc: Optional[bytes] = None
    sealed_store: Optional["SealedStore"] = None
    # note: no on-disk dirs/paths anymore

    def _oqs_kem_name(self) -> Optional[str]: ...
    def _load_or_create_hybrid_keys(self) -> None: ...
    def _decrypt_x25519_priv(self) -> x25519.X25519PrivateKey: ...
    def _decrypt_pq_priv(self) -> Optional[bytes]: ...
    def _load_or_create_signing(self) -> None: ...
    def _decrypt_sig_priv(self) -> bytes: ...
    def sign_blob(self, data: bytes) -> bytes: ...
    def verify_blob(self, pub: bytes, sig_bytes: bytes, data: bytes) -> bool: ...

    def __init__(self, passphrase_env_var: str = 'ENCRYPTION_PASSPHRASE'):
        self.encryption_key = None
        self.passphrase_env_var = passphrase_env_var
        self.backend = default_backend()
        self._sealed_cache: Optional[SealedCache] = None
        self._pq_alg_name = None
        self.x25519_pub = b""
        self._x25519_priv_enc = b""
        self.pq_pub = None
        self._pq_priv_enc = None
        self.sig_alg_name = None
        self.sig_pub = None
        self._sig_priv_enc = None
        self.sealed_store = None
        self._load_encryption_key()

    def _load_encryption_key(self):
        if self.encryption_key is not None:
            return

        passphrase = os.getenv(self.passphrase_env_var)
        if not passphrase:
            logger.critical(f"The environment variable {self.passphrase_env_var} is not set.")
            raise ValueError(f"No {self.passphrase_env_var} environment variable set")

        salt = _b64get(ENV_SALT_B64, required=True)
        try:
            kdf = Scrypt(salt=salt, length=32, n=65536, r=8, p=1, backend=self.backend)
            self.encryption_key = kdf.derive(passphrase.encode())
            logger.info("Encryption key successfully derived (env salt).")
        except Exception as e:
            logger.error(f"Failed to derive encryption key: {e}")
            raise

    def get_key(self):
        if not self.encryption_key:
            logger.error("Encryption key is not initialized.")
            raise ValueError("Encryption key is not initialized.")
        return self.encryption_key

MAGIC_PQ2_PREFIX = "PQ2."
HYBRID_ALG_ID    = "HY1"  
WRAP_INFO        = b"QRS|hybrid-wrap|v1"
DATA_INFO        = b"QRS|data-aesgcm|v1"


COMPRESS_MIN   = int(os.getenv("QRS_COMPRESS_MIN", "512"))    
ENV_CAP_BYTES  = int(os.getenv("QRS_ENV_CAP_BYTES", "131072"))  


POLICY = {
    "min_env_version": "QRS2",
    "require_sig_on_pq2": True,
    "require_pq_if_available": False, 
}

SIG_ALG_IDS = {
    "ML-DSA-87": ("ML-DSA-87", "MLD3"),
    "ML-DSA-65": ("ML-DSA-65", "MLD2"),
    "Dilithium5": ("Dilithium5", "MLD5"),
    "Dilithium3": ("Dilithium3", "MLD3"),
    "Ed25519": ("Ed25519", "ED25"),
}


def b64e(b: bytes) -> str: return base64.b64encode(b).decode("utf-8")
def b64d(s: str) -> bytes: return base64.b64decode(s.encode("utf-8"))

def hkdf_sha3(key_material: bytes, info: bytes = b"", length: int = 32, salt: Optional[bytes] = None) -> bytes:
    hkdf = HKDF(algorithm=SHA3_512(), length=length, salt=salt, info=info, backend=default_backend())
    return hkdf.derive(key_material)

def _canon_json(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")

def _fp8(data: bytes) -> str:
    return hashlib.blake2s(data or b"", digest_size=8).hexdigest()

def _compress_payload(data: bytes) -> tuple[str, bytes, int]:
    if len(data) < COMPRESS_MIN:
        return ("none", data, len(data))
    if _HAS_ZSTD and zstd is not None:
        c = zstd.ZstdCompressor(level=8).compress(data); alg = "zstd"
    else:
        c = _zlib.compress(data, 7);                      alg = "deflate"
    if len(c) >= int(0.98 * len(data)):
        return ("none", data, len(data))
    return (alg, c, len(data))

def _decompress_payload(alg: str, blob: bytes, orig_len: Optional[int] = None) -> bytes:
    if alg in (None, "", "none"):
        return blob
    if alg == "zstd" and _HAS_ZSTD and zstd is not None:
        max_out = (orig_len or (len(blob) * 80) + 1)
        return zstd.ZstdDecompressor().decompress(blob, max_output_size=max_out)
    if alg == "deflate":
        return _zlib.decompress(blob)
    raise ValueError("Unsupported compression algorithm")

QID25 = [
    ("A1","Crimson","#d7263d"), ("A2","Magenta","#ff2e88"), ("A3","Fuchsia","#cc2fcb"),
    ("A4","Royal","#5b2a86"),  ("A5","Indigo","#4332cf"), ("B1","Azure","#1f7ae0"),
    ("B2","Cerulean","#2bb3ff"),("B3","Cyan","#00e5ff"),  ("B4","Teal","#00c2a8"),
    ("B5","Emerald","#00b263"), ("C1","Lime","#8bd346"),  ("C2","Chartreuse","#b3f442"),
    ("C3","Yellow","#ffd400"),  ("C4","Amber","#ffb300"), ("C5","Tangerine","#ff8f1f"),
    ("D1","Orange","#ff6a00"),  ("D2","Vermilion","#ff3b1f"),("D3","Coral","#ff5a7a"),
    ("D4","Rose","#ff7597"),    ("D5","Blush","#ff9ab5"), ("E1","Plum","#7a4eab"),
    ("E2","Violet","#9a66e2"),  ("E3","Periwinkle","#9fb6ff"),("E4","Mint","#99f3d6"),
    ("E5","Sand","#e4d5a1"),
]
def _hex_to_rgb01(h):
    h = h.lstrip("#"); return (int(h[0:2],16)/255.0, int(h[2:4],16)/255.0, int(h[4:6],16)/255.0)
def _rgb01_to_hex(r,g,b):
    return "#{:02x}{:02x}{:02x}".format(int(max(0,min(1,r))*255),int(max(0,min(1,g))*255),int(max(0,min(1,b))*255))
    
def _approx_oklch_from_rgb(r: float, g: float, b: float) -> tuple[float, float, float]:

   
    r = 0.0 if r < 0.0 else 1.0 if r > 1.0 else r
    g = 0.0 if g < 0.0 else 1.0 if g > 1.0 else g
    b = 0.0 if b < 0.0 else 1.0 if b > 1.0 else b

    hue_hls, light_hls, sat_hls = colorsys.rgb_to_hls(r, g, b)


    luma = 0.2126 * r + 0.7152 * g + 0.0722 * b

 
    L = 0.6 * light_hls + 0.4 * luma

 
    C = sat_hls * 0.37

   
    H = (hue_hls * 360.0) % 360.0

    return (round(L, 4), round(C, 4), round(H, 2))


class ColorSync:
    def __init__(self) -> None:
        self._epoch = secrets.token_bytes(16)

    def sample(self) -> dict:
        try:
            cpu, ram = get_cpu_ram_usage()
        except Exception:
            cpu, ram = 0.0, 0.0

        pool_parts = [
            secrets.token_bytes(32),
            os.urandom(32),
            uuid.uuid4().bytes,
            str((time.time_ns(), time.perf_counter_ns())).encode(),
            f"{os.getpid()}:{os.getppid()}:{threading.get_ident()}".encode(),
            int(cpu * 100).to_bytes(2, "big"),
            int(ram * 100).to_bytes(2, "big"),
            self._epoch,
        ]
        pool = b"|".join(pool_parts)

        h = hashlib.sha3_512(pool).digest()
        hue = int.from_bytes(h[0:2], "big") / 65535.0
        sat = min(1.0, 0.35 + (cpu / 100.0) * 0.6)
        lig = min(1.0, 0.35 + (1.0 - (ram / 100.0)) * 0.55)

        r, g, b = colorsys.hls_to_rgb(hue, lig, sat)
        hexc = _rgb01_to_hex(r, g, b)
        L, C, H = _approx_oklch_from_rgb(r, g, b)

        best = None
        best_d = float("inf")
        for code, name, hexq in QID25:
            rq, gq, bq = _hex_to_rgb01(hexq)
            hq, lq, sq = colorsys.rgb_to_hls(rq, gq, bq)
            d = abs(hq - hue) + abs(lq - lig) + abs(sq - sat)
            if d < best_d:
                best_d = d
                best = (code, name, hexq)

        if best is None:
            best = ("", "", hexc)

        return {
            "entropy_norm": 1.0,
            "hsl": {"h": round(hue * 360.0, 2), "s": round(sat, 3), "l": round(lig, 3)},
            "oklch": {"L": L, "C": C, "H": H},
            "hex": hexc,
            "qid25": {"code": best[0], "name": best[1], "hex": best[2]},
            "epoch": base64.b16encode(self._epoch[:6]).decode(),
        }

    def bump_epoch(self) -> None:
        self._epoch = hashlib.blake2b(
            self._epoch + os.urandom(16), digest_size=16
        ).digest()


colorsync = ColorSync()


def _gf256_mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _gf256_pow(a: int, e: int) -> int:
    x = 1
    while e:
        if e & 1:
            x = _gf256_mul(x, a)
        a = _gf256_mul(a, a)
        e >>= 1
    return x


def _gf256_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError
    return _gf256_pow(a, 254)


def shamir_recover(shares: list[tuple[int, bytes]], t: int) -> bytes:
    if len(shares) < t:
        raise ValueError("not enough shares")

    length = len(shares[0][1])
    parts = shares[:t]
    out = bytearray(length)

    for i in range(length):
        val = 0
        for j, (xj, yj) in enumerate(parts):
            num = 1
            den = 1
            for m, (xm, _) in enumerate(parts):
                if m == j:
                    continue
                num = _gf256_mul(num, xm)
                den = _gf256_mul(den, xj ^ xm)
            lj0 = _gf256_mul(num, _gf256_inv(den))
            val ^= _gf256_mul(yj[i], lj0)
        out[i] = val

    return bytes(out)


SEALED_DIR   = Path("./sealed_store")
SEALED_FILE  = SEALED_DIR / "sealed.json.enc"
SEALED_VER   = "SS1"
SHARDS_ENV   = "QRS_SHARDS_JSON"



@dataclass(frozen=True, slots=True)   
class SealedRecord:
    v: str
    created_at: int
    kek_ver: int
    kem_alg: str
    sig_alg: str
    x25519_priv: str
    pq_priv: str
    sig_priv: str


class SealedStore:
    def __init__(self, km: "KeyManager"):
        self.km = km  # no dirs/files created

    def _derive_split_kek(self, base_kek: bytes) -> bytes:
        shards_b64 = os.getenv(SHARDS_ENV, "")
        if shards_b64:
            try:
                payload = json.loads(base64.urlsafe_b64decode(shards_b64.encode()).decode())
                shares = [(int(s["x"]), base64.b64decode(s["y"])) for s in payload]
                secret = shamir_recover(shares, t=max(2, min(5, len(shares))))
            except Exception:
                secret = b"\x00"*32
        else:
            secret = b"\x00"*32
        return hkdf_sha3(base_kek + secret, info=b"QRS|split-kek|v1", length=32)

    def _seal(self, kek: bytes, data: dict) -> bytes:
        jj = json.dumps(data, separators=(",",":")).encode()
        n = secrets.token_bytes(12)
        ct = AESGCM(kek).encrypt(n, jj, b"sealed")
        return json.dumps({"v":SEALED_VER,"n":b64e(n),"ct":b64e(ct)}, separators=(",",":")).encode()

    def _unseal(self, kek: bytes, blob: bytes) -> dict:
        obj = json.loads(blob.decode())
        if obj.get("v") != SEALED_VER: raise ValueError("sealed ver mismatch")
        n = b64d(obj["n"]); ct = b64d(obj["ct"])
        pt = AESGCM(kek).decrypt(n, ct, b"sealed")
        return json.loads(pt.decode())

    def exists(self) -> bool:
        return bool(os.getenv(ENV_SEALED_B64))

    def save_from_current_keys(self):
        try:
            x_priv = self.km._decrypt_x25519_priv().private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            pq_priv = self.km._decrypt_pq_priv() or b""
            sig_priv = self.km._decrypt_sig_priv()

            rec = {
                "v": SEALED_VER, "created_at": int(time.time()), "kek_ver": 1,
                "kem_alg": self.km._pq_alg_name or "", "sig_alg": self.km.sig_alg_name or "",
                "x25519_priv": b64e(x_priv), "pq_priv": b64e(pq_priv), "sig_priv": b64e(sig_priv)
            }

            passphrase = os.getenv(self.km.passphrase_env_var) or ""
            salt = _b64get(ENV_SALT_B64, required=True)
            base_kek = hash_secret_raw(
                passphrase.encode(), salt,
                3, 512*1024, max(2, (os.cpu_count() or 2)//2), 32, ArgonType.ID
            )
            split_kek = self._derive_split_kek(base_kek)
            blob = self._seal(split_kek, rec)
            _b64set(ENV_SEALED_B64, blob)
            logger.info("Sealed store saved to env.")
        except Exception as e:
            logger.error(f"Sealed save failed: {e}", exc_info=True)

    def load_into_km(self) -> bool:
        try:
            blob = _b64get(ENV_SEALED_B64, required=False)
            if not blob:
                return False

            passphrase = os.getenv(self.km.passphrase_env_var) or ""
            salt = _b64get(ENV_SALT_B64, required=True)
            base_kek = hash_secret_raw(
                passphrase.encode(), salt,
                3, 512*1024, max(2, (os.cpu_count() or 2)//2), 32, ArgonType.ID
            )
            split_kek = self._derive_split_kek(base_kek)
            rec = self._unseal(split_kek, blob)

            cache: SealedCache = {
                "x25519_priv_raw": b64d(rec["x25519_priv"]),
                "pq_priv_raw": (b64d(rec["pq_priv"]) if rec.get("pq_priv") else None),
                "sig_priv_raw": b64d(rec["sig_priv"]),
                "kem_alg": rec.get("kem_alg", ""),
                "sig_alg": rec.get("sig_alg", ""),
            }
            self.km._sealed_cache = cache
            if cache.get("kem_alg"):
                self.km._pq_alg_name = cache["kem_alg"] or None
            if cache.get("sig_alg"):
                self.km.sig_alg_name = cache["sig_alg"] or self.km.sig_alg_name

            logger.info("Sealed store loaded from env into KeyManager cache.")
            return True
        except Exception as e:
            logger.error(f"Sealed load failed: {e}")
            return False
def _km_oqs_kem_name(self) -> Optional[str]:
    if oqs is None:
        return None
    oqs_mod = cast(Any, oqs)
    for n in ("ML-KEM-768","Kyber768","FIPS204-ML-KEM-768"):
        try:
            oqs_mod.KeyEncapsulation(n)
            return n
        except Exception:
            continue
    return None




def _try(f: Callable[[], Any]) -> bool:
    try:
        f()
        return True
    except Exception:
        return False
        

STRICT_PQ2_ONLY = bool(int(os.getenv("STRICT_PQ2_ONLY", "1")))

def _km_load_or_create_hybrid_keys(self: "KeyManager") -> None:
    """
    Populate hybrid (x25519 + optional PQ KEM) key handles from ENV,
    falling back to the sealed cache when present. No files are touched.
    """
    cache = getattr(self, "_sealed_cache", None)

    # ---- X25519 ----
    x_pub_b   = _b64get(ENV_X25519_PUB_B64, required=False)
    x_privenc = _b64get(ENV_X25519_PRIV_ENC_B64, required=False)

    if x_pub_b:
        # Env has the raw public key
        self.x25519_pub = x_pub_b
    elif cache and cache.get("x25519_priv_raw"):
        # Derive pub from sealed raw private (env didn't provide pub)
        self.x25519_pub = (
            x25519.X25519PrivateKey
            .from_private_bytes(cache["x25519_priv_raw"])
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        )
        logger.info("x25519 public key derived from sealed cache.")
    else:
        raise RuntimeError("x25519 key material not found (neither ENV nor sealed cache).")

    # If env doesn't carry the encrypted private, leave it empty;
    # _decrypt_x25519_priv() will use the sealed cache path.
    self._x25519_priv_enc = x_privenc or b""

    # ---- PQ KEM (ML-KEM) ----
    # Prefer ENV alg; fall back to sealed cache hint
    self._pq_alg_name = os.getenv(ENV_PQ_KEM_ALG) or None
    if not self._pq_alg_name and cache and cache.get("kem_alg"):
        self._pq_alg_name = str(cache["kem_alg"]) or None

    pq_pub_b   = _b64get(ENV_PQ_PUB_B64, required=False)
    pq_privenc = _b64get(ENV_PQ_PRIV_ENC_B64, required=False)

    # Store what we have (pub for encap; priv_enc for decap via env path)
    self.pq_pub       = pq_pub_b or None
    self._pq_priv_enc = pq_privenc or None

    # In strict mode we must have: alg + pub + (priv via env or sealed cache)
    if STRICT_PQ2_ONLY:
        have_priv = bool(pq_privenc) or bool(cache and cache.get("pq_priv_raw"))
        if not (self._pq_alg_name and self.pq_pub and have_priv):
            raise RuntimeError("Strict PQ2 mode: ML-KEM keys not fully available (need alg+pub+priv).")

    # Log what we ended up with (helps debugging)
    logger.info(
        "Hybrid keys loaded: x25519_pub=%s, pq_alg=%s, pq_pub=%s, pq_priv=%s (sealed=%s)",
        "yes" if self.x25519_pub else "no",
        self._pq_alg_name or "none",
        "yes" if self.pq_pub else "no",
        "yes" if (pq_privenc or (cache and cache.get('pq_priv_raw'))) else "no",
        "yes" if cache else "no",
    )

def _km_decrypt_x25519_priv(self: "KeyManager") -> x25519.X25519PrivateKey:
    cache = getattr(self, "_sealed_cache", None)
    if cache is not None and "x25519_priv_raw" in cache:
        raw = cache["x25519_priv_raw"]
        return x25519.X25519PrivateKey.from_private_bytes(raw)

    x_enc = cast(bytes, getattr(self, "_x25519_priv_enc"))
    passphrase = os.getenv(self.passphrase_env_var) or ""
    salt = _b64get(ENV_SALT_B64, required=True)
    kek = hash_secret_raw(passphrase.encode(), salt, 3, 512*1024, max(2, (os.cpu_count() or 2)//2), 32, ArgonType.ID)
    aes = AESGCM(kek)
    n, ct = x_enc[:12], x_enc[12:]
    raw = aes.decrypt(n, ct, b"x25519")
    return x25519.X25519PrivateKey.from_private_bytes(raw)
    
def _km_decrypt_pq_priv(self: "KeyManager") -> Optional[bytes]:
    """
    Return the raw ML-KEM private key bytes suitable for oqs decapsulation.
    Prefers sealed cache; falls back to ENV-encrypted key if present.
    """
    # Prefer sealed cache (already raw)
    cache = getattr(self, "_sealed_cache", None)
    if cache is not None and cache.get("pq_priv_raw") is not None:
        return cache.get("pq_priv_raw")

    # Otherwise try the env-encrypted private key
    pq_alg = getattr(self, "_pq_alg_name", None)
    pq_enc = getattr(self, "_pq_priv_enc", None)
    if not (pq_alg and pq_enc):
        return None

    passphrase = os.getenv(self.passphrase_env_var) or ""
    salt = _b64get(ENV_SALT_B64, required=True)
    kek = hash_secret_raw(
        passphrase.encode(), salt,
        3, 512 * 1024, max(2, (os.cpu_count() or 2) // 2),
        32, ArgonType.ID
    )
    aes = AESGCM(kek)
    n, ct = pq_enc[:12], pq_enc[12:]
    return aes.decrypt(n, ct, b"pqkem")


def _km_decrypt_sig_priv(self: "KeyManager") -> bytes:
    """
    Decrypts signature SK from ENV using Argon2id(passphrase + ENV_SALT_B64).
    If a sealed_cache is present, returns raw from cache.
    """
    # Prefer sealed cache if available
    cache = getattr(self, "_sealed_cache", None)
    if cache is not None and "sig_priv_raw" in cache:
        return cache["sig_priv_raw"]

    sig_enc = getattr(self, "_sig_priv_enc", None)
    if not sig_enc:
        raise RuntimeError("Signature private key not available in env.")

    passphrase = os.getenv(self.passphrase_env_var) or ""
    if not passphrase:
        raise RuntimeError(f"{self.passphrase_env_var} not set")

    salt = _b64get(ENV_SALT_B64, required=True)
    kek = hash_secret_raw(
        passphrase.encode(), salt,
        3, 512 * 1024, max(2, (os.cpu_count() or 2)//2),
        32, ArgonType.ID
    )
    aes = AESGCM(kek)

    n, ct = sig_enc[:12], sig_enc[12:]
    label = b"pqsig" if (self.sig_alg_name or "").startswith(("ML-DSA", "Dilithium")) else b"ed25519"
    return aes.decrypt(n, ct, label)

def _oqs_sig_name() -> Optional[str]:
    if oqs is None:
        return None
    oqs_mod = cast(Any, oqs)
    for name in ("ML-DSA-87","ML-DSA-65","Dilithium5","Dilithium3"):
        try:
            oqs_mod.Signature(name)
            return name
        except Exception:
            continue
    return None


def _km_load_or_create_signing(self: "KeyManager") -> None:
    """
    ENV-only:
      - Reads PQ/Ed25519 signing keys from ENV, or creates+stores them in ENV if missing.
      - Private key is AESGCM( Argon2id( passphrase + ENV_SALT_B64 ) ).
    Requires bootstrap_env_keys() to have set ENV_SALT_B64 at minimum.
    """
    # Try to read from ENV first
    alg = os.getenv(ENV_SIG_ALG) or None
    pub = _b64get(ENV_SIG_PUB_B64, required=False)
    enc = _b64get(ENV_SIG_PRIV_ENC_B64, required=False)

    if not (alg and pub and enc):
        # Need to generate keys and place into ENV
        passphrase = os.getenv(self.passphrase_env_var) or ""
        if not passphrase:
            raise RuntimeError(f"{self.passphrase_env_var} not set")

        salt = _b64get(ENV_SALT_B64, required=True)
        kek = hash_secret_raw(
            passphrase.encode(), salt,
            3, 512 * 1024, max(2, (os.cpu_count() or 2)//2),
            32, ArgonType.ID
        )
        aes = AESGCM(kek)

        try_pq = _oqs_sig_name() if oqs is not None else None
        if try_pq:
            # Generate PQ signature (ML-DSA/Dilithium)
            with oqs.Signature(try_pq) as s:  # type: ignore[attr-defined]
                pub_raw = s.generate_keypair()
                sk_raw  = s.export_secret_key()
            n = secrets.token_bytes(12)
            enc_raw = n + aes.encrypt(n, sk_raw, b"pqsig")
            os.environ[ENV_SIG_ALG] = try_pq
            _b64set(ENV_SIG_PUB_B64, pub_raw)
            _b64set(ENV_SIG_PRIV_ENC_B64, enc_raw)
            alg, pub, enc = try_pq, pub_raw, enc_raw
            logger.info("Generated PQ signature keypair (%s) into ENV.", try_pq)
        else:
            if STRICT_PQ2_ONLY:
                raise RuntimeError("Strict PQ2 mode: ML-DSA signature required, but oqs unavailable.")
            # Ed25519 fallback
            kp  = ed25519.Ed25519PrivateKey.generate()
            pub_raw = kp.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            sk_raw  = kp.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption()
            )
            n = secrets.token_bytes(12)
            enc_raw = n + aes.encrypt(n, sk_raw, b"ed25519")
            os.environ[ENV_SIG_ALG] = "Ed25519"
            _b64set(ENV_SIG_PUB_B64, pub_raw)
            _b64set(ENV_SIG_PRIV_ENC_B64, enc_raw)
            alg, pub, enc = "Ed25519", pub_raw, enc_raw
            logger.info("Generated Ed25519 signature keypair into ENV (fallback).")

    # Cache into the instance
    self.sig_alg_name = alg
    self.sig_pub = pub
    self._sig_priv_enc = enc

    if STRICT_PQ2_ONLY and not (self.sig_alg_name or "").startswith(("ML-DSA", "Dilithium")):
        raise RuntimeError("Strict PQ2 mode: ML-DSA (Dilithium) signature required in env.")


def _km_sign(self, data: bytes) -> bytes:
    if (getattr(self, "sig_alg_name", "") or "").startswith("ML-DSA"):
        if oqs is None:
            raise RuntimeError("PQ signature requested but oqs is unavailable")
        oqs_mod = cast(Any, oqs)
        with oqs_mod.Signature(self.sig_alg_name, _km_decrypt_sig_priv(self)) as sig:
            return sig.sign(data)
    else:
        return ed25519.Ed25519PrivateKey.from_private_bytes(
            _km_decrypt_sig_priv(self)
        ).sign(data)

def _km_verify(self, pub: bytes, sig_bytes: bytes, data: bytes) -> bool:
    try:
        if (getattr(self, "sig_alg_name", "") or "").startswith("ML-DSA"):
            if oqs is None:
                return False
            oqs_mod = cast(Any, oqs)
            with oqs_mod.Signature(self.sig_alg_name) as s:
                return s.verify(data, sig_bytes, pub)
        else:
            ed25519.Ed25519PublicKey.from_public_bytes(pub).verify(sig_bytes, data)
            return True
    except Exception:
        return False

# === Bind KeyManager monkeypatched methods (do this once, at the end) ===
# === Bind KeyManager monkeypatched methods (ENV-only) ===
_KM = cast(Any, KeyManager)
_KM._oqs_kem_name               = _km_oqs_kem_name
_KM._load_or_create_hybrid_keys = _km_load_or_create_hybrid_keys
_KM._decrypt_x25519_priv        = _km_decrypt_x25519_priv
_KM._decrypt_pq_priv            = _km_decrypt_pq_priv
_KM._load_or_create_signing     = _km_load_or_create_signing   # <-- ENV version
_KM._decrypt_sig_priv           = _km_decrypt_sig_priv         # <-- ENV version
_KM.sign_blob                   = _km_sign
_KM.verify_blob                 = _km_verify


HD_FILE = Path("./sealed_store/hd_epoch.json")


def hd_get_epoch() -> int:
    try:
        if HD_FILE.exists():
            return int(json.loads(HD_FILE.read_text()).get("epoch", 1))
    except Exception:
        pass
    return 1


def hd_rotate_epoch() -> int:
    ep = hd_get_epoch() + 1
    HD_FILE.parent.mkdir(parents=True, exist_ok=True)
    HD_FILE.write_text(json.dumps({"epoch": ep, "rotated_at": int(time.time())}))
    HD_FILE.chmod(0o600)
    try:
        colorsync.bump_epoch()
    except Exception:
        pass
    return ep


def _rootk() -> bytes:
    return hkdf_sha3(encryption_key, info=b"QRS|rootk|v1", length=32)


def derive_domain_key(domain: str, field: str, epoch: int) -> bytes:
    info = f"QRS|dom|{domain}|{field}|epoch={epoch}".encode()
    return hkdf_sha3(_rootk(), info=info, length=32)


def build_hd_ctx(domain: str, field: str, rid: int | None = None) -> dict:
    return {
        "domain": domain,
        "field": field,
        "epoch": hd_get_epoch(),
        "rid": int(rid or 0),
    }


class DecryptionGuard:
    def __init__(self, capacity: int = 40, refill_per_min: int = 20) -> None:
        self.capacity = capacity
        self.tokens = capacity
        self.refill_per_min = refill_per_min
        self.last = time.time()
        self.lock = threading.Lock()

    def _refill(self) -> None:
        now = time.time()
        add = (self.refill_per_min / 60.0) * (now - self.last)
        if add > 0:
            self.tokens = min(self.capacity, self.tokens + add)
            self.last = now

    def register_failure(self) -> bool:
        with self.lock:
            self._refill()
            if self.tokens >= 1:
                self.tokens -= 1
                time.sleep(random.uniform(0.05, 0.25))
                return True
            return False

dec_guard = DecryptionGuard()
AUDIT_FILE = Path("./sealed_store/audit.log")

class AuditTrail:
    def __init__(self, km: "KeyManager"):
        self.km = km
        AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)

    def _key(self) -> bytes:
        passphrase = os.getenv(self.km.passphrase_env_var) or ""
        salt = _b64get(ENV_SALT_B64, required=True)
        base_kek = hash_secret_raw(
            passphrase.encode(),
            salt,
            time_cost=3,
            memory_cost=512 * 1024,
            parallelism=max(2, (os.cpu_count() or 2) // 2),
            hash_len=32,
            type=ArgonType.ID,
        )

        sealed_store = getattr(self.km, "sealed_store", None)
        if isinstance(sealed_store, SealedStore):
            split_kek = sealed_store._derive_split_kek(base_kek)
        else:
            split_kek = hkdf_sha3(base_kek, info=b"QRS|split-kek|v1", length=32)

        return hkdf_sha3(split_kek, info=b"QRS|audit|v1", length=32)
    def _last_hash(self) -> str:
        try:
            with AUDIT_FILE.open("rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                if size == 0:
                    return "GENESIS"
                back = min(8192, size)
                f.seek(size - back)
                lines = f.read().splitlines()
                if not lines:
                    return "GENESIS"
                return json.loads(lines[-1].decode()).get("h", "GENESIS")
        except Exception:
            return "GENESIS"

    def append(self, event: str, data: dict, actor: str = "system"):
        try:
            ent = {
                "ts": int(time.time()),
                "actor": actor,
                "event": event,
                "data": data,
                "prev": self._last_hash(),
            }
            j = json.dumps(ent, separators=(",", ":")).encode()
            h = hashlib.sha3_256(j).hexdigest()
            n = secrets.token_bytes(12)
            ct = AESGCM(self._key()).encrypt(n, j, b"audit")
            rec = json.dumps({"n": b64e(n), "ct": b64e(ct), "h": h}, separators=(",", ":")) + "\n"
            with AUDIT_FILE.open("a", encoding="utf-8") as f:
                f.write(rec)
                AUDIT_FILE.chmod(0o600)
        except Exception as e:
            logger.error(f"audit append failed: {e}", exc_info=True)

    def verify(self) -> dict:
        ok = True
        count = 0
        prev = "GENESIS"
        try:
            key = self._key()
            with AUDIT_FILE.open("rb") as f:
                for line in f:
                    if not line.strip():
                        continue
                    obj = json.loads(line.decode())
                    pt = AESGCM(key).decrypt(b64d(obj["n"]), b64d(obj["ct"]), b"audit")
                    if hashlib.sha3_256(pt).hexdigest() != obj["h"]:
                        ok = False
                        break
                    ent = json.loads(pt.decode())
                    if ent.get("prev") != prev:
                        ok = False
                        break
                    prev = obj["h"]
                    count += 1
            return {"ok": ok, "entries": count, "tip": prev}
        except Exception as e:
            logger.error(f"audit verify failed: {e}", exc_info=True)
            return {"ok": False, "entries": 0, "tip": ""}

    def tail(self, limit: int = 20) -> list[dict]:
        out: list[dict] = []
        try:
            key = self._key()
            lines = AUDIT_FILE.read_text(encoding="utf-8").splitlines()
            for line in lines[-max(1, min(100, limit)):]:
                obj = json.loads(line)
                pt = AESGCM(key).decrypt(b64d(obj["n"]), b64d(obj["ct"]), b"audit")
                ent = json.loads(pt.decode())
                out.append(
                    {
                        "ts": ent["ts"],
                        "actor": ent["actor"],
                        "event": ent["event"],
                        "data": ent["data"],
                    }
                )
        except Exception as e:
            logger.error(f"audit tail failed: {e}", exc_info=True)
        return out

# 1) Generate any missing keys/salt/signing material into ENV (no files)
bootstrap_env_keys(
    strict_pq2=STRICT_PQ2_ONLY,
    echo_exports=bool(int(os.getenv("QRS_BOOTSTRAP_SHOW","0")))
)

# 2) Proceed as usual, but everything now comes from ENV
key_manager = KeyManager()
encryption_key = key_manager.get_key()
key_manager._sealed_cache = None
key_manager.sealed_store = SealedStore(key_manager)

# (Optional sealed cache in ENV – doesn't create files)
if not key_manager.sealed_store.exists() and os.getenv("QRS_ENABLE_SEALED","1")=="1":
    key_manager._load_or_create_hybrid_keys()
    key_manager._load_or_create_signing()
    key_manager.sealed_store.save_from_current_keys()
if key_manager.sealed_store.exists():
    key_manager.sealed_store.load_into_km()

# Ensure runtime key handles are populated from ENV (no file paths)
key_manager._load_or_create_hybrid_keys()
key_manager._load_or_create_signing()

audit = AuditTrail(key_manager)
audit.append("boot", {"sealed_loaded": bool(getattr(key_manager, "_sealed_cache", None))})

key_manager._sealed_cache = None
key_manager.sealed_store = SealedStore(key_manager)
if not key_manager.sealed_store.exists() and os.getenv("QRS_ENABLE_SEALED","1")=="1":
    key_manager._load_or_create_hybrid_keys()
    key_manager._load_or_create_signing()
    key_manager.sealed_store.save_from_current_keys()
if key_manager.sealed_store.exists():
    key_manager.sealed_store.load_into_km()

key_manager._load_or_create_hybrid_keys()
key_manager._load_or_create_signing()

audit = AuditTrail(key_manager)
audit.append("boot", {"sealed_loaded": bool(getattr(key_manager, "_sealed_cache", None))})


def encrypt_data(data: Any, ctx: Optional[Mapping[str, Any]] = None) -> Optional[str]:
    try:
        if data is None:
            return None
        if not isinstance(data, bytes):
            data = str(data).encode()

        comp_alg, pt_comp, orig_len = _compress_payload(data)
        dek = secrets.token_bytes(32)
        data_nonce = secrets.token_bytes(12)
        data_ct = AESGCM(dek).encrypt(data_nonce, pt_comp, None)


        if STRICT_PQ2_ONLY and not (key_manager._pq_alg_name and getattr(key_manager, "pq_pub", None)):
            raise RuntimeError("Strict PQ2 mode requires ML-KEM; liboqs and PQ KEM keys must be present.")

        x_pub: bytes = key_manager.x25519_pub
        if not x_pub:
            raise RuntimeError("x25519 public key not initialized (used alongside PQ KEM in hybrid wrap)")

       
        eph_priv = x25519.X25519PrivateKey.generate()
        eph_pub = eph_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        ss_x = eph_priv.exchange(x25519.X25519PublicKey.from_public_bytes(x_pub))

   
        pq_ct: bytes = b""
        ss_pq: bytes = b""
        if key_manager._pq_alg_name and oqs is not None and getattr(key_manager, "pq_pub", None):
            oqs_mod = cast(Any, oqs)
            with oqs_mod.KeyEncapsulation(key_manager._pq_alg_name) as kem:
                pq_ct, ss_pq = kem.encap_secret(cast(bytes, key_manager.pq_pub))
        else:
            if STRICT_PQ2_ONLY:
                raise RuntimeError("Strict PQ2 mode: PQ KEM public key not available.")

       
        col = colorsync.sample()
        col_info = json.dumps(
            {
                "qid25": col["qid25"]["code"],
                "hx": col["hex"],
                "en": col["entropy_norm"],
                "ep": col["epoch"],
            },
            separators=(",", ":"),
        ).encode()

   
        hd_ctx: Optional[dict[str, Any]] = None
        dk: bytes = b""
        if isinstance(ctx, Mapping) and ctx.get("domain"):
            ep = int(ctx.get("epoch", hd_get_epoch()))
            field = str(ctx.get("field", ""))
            dk = derive_domain_key(str(ctx["domain"]), field, ep)
            hd_ctx = {
                "domain": str(ctx["domain"]),
                "field": field,
                "epoch": ep,
                "rid": int(ctx.get("rid", 0)),
            }

 
        wrap_info = WRAP_INFO + b"|" + col_info + (b"|HD" if hd_ctx else b"")
        wrap_key = hkdf_sha3(ss_x + ss_pq + dk, info=wrap_info, length=32)
        wrap_nonce = secrets.token_bytes(12)
        dek_wrapped = AESGCM(wrap_key).encrypt(wrap_nonce, dek, None)


        env: dict[str, Any] = {
            "v": "QRS2",
            "alg": HYBRID_ALG_ID,
            "pq_alg": key_manager._pq_alg_name or "",
            "pq_ct": b64e(pq_ct),
            "x_ephemeral_pub": b64e(eph_pub),
            "wrap_nonce": b64e(wrap_nonce),
            "dek_wrapped": b64e(dek_wrapped),
            "data_nonce": b64e(data_nonce),
            "data_ct": b64e(data_ct),
            "comp": {"alg": comp_alg, "orig_len": orig_len},
            "col_meta": {
                "qid25": col["qid25"]["code"],
                "qid25_hex": col["qid25"]["hex"],
                "hex": col["hex"],
                "oklch": col["oklch"],
                "hsl": col["hsl"],
                "entropy_norm": col["entropy_norm"],
                "epoch": col["epoch"],
            },
        }
        if hd_ctx:
            env["hd_ctx"] = hd_ctx

        core = {
            "v": env["v"],
            "alg": env["alg"],
            "pq_alg": env["pq_alg"],
            "pq_ct": env["pq_ct"],
            "x_ephemeral_pub": env["x_ephemeral_pub"],
            "wrap_nonce": env["wrap_nonce"],
            "dek_wrapped": env["dek_wrapped"],
            "data_nonce": env["data_nonce"],
            "data_ct": env["data_ct"],
            "comp": env["comp"],
            "col_meta": env["col_meta"],
            "policy": {
                "min_env_version": POLICY["min_env_version"],
                "require_sig_on_pq2": POLICY["require_sig_on_pq2"],
                "require_pq_if_available": POLICY["require_pq_if_available"],
            },
            "hd_ctx": env.get("hd_ctx", {}),
        }
        sig_payload = _canon_json(core)


        sig_alg_name: str = key_manager.sig_alg_name or ""
        if STRICT_PQ2_ONLY and not (sig_alg_name.startswith("ML-DSA") or sig_alg_name.startswith("Dilithium")):
            raise RuntimeError("Strict PQ2 mode requires ML-DSA (Dilithium) signatures.")
        sig_raw = key_manager.sign_blob(sig_payload)

        alg_id_short = SIG_ALG_IDS.get(sig_alg_name, ("Ed25519", "ED25"))[1]
        sig_pub_b = cast(Optional[bytes], key_manager.sig_pub)
        if sig_pub_b is None:
            raise RuntimeError("Signature public key not available")

        env["sig"] = {
            "alg": sig_alg_name,
            "alg_id": alg_id_short,
            "pub": b64e(sig_pub_b),
            "fp8": _fp8(sig_pub_b),
            "val": b64e(sig_raw),
        }

        blob_json = json.dumps(env, separators=(",", ":")).encode()
        if len(blob_json) > ENV_CAP_BYTES:
            logger.error(f"Envelope too large ({len(blob_json)}B > {ENV_CAP_BYTES}B)")
            return None

        return MAGIC_PQ2_PREFIX + base64.urlsafe_b64encode(blob_json).decode()

    except Exception as e:
        logger.error(f"PQ2 encrypt failed: {e}", exc_info=True)
        return None



def decrypt_data(encrypted_data_b64: str) -> Optional[str]:
    try:
      
        if isinstance(encrypted_data_b64, str) and encrypted_data_b64.startswith(MAGIC_PQ2_PREFIX):
            raw = base64.urlsafe_b64decode(encrypted_data_b64[len(MAGIC_PQ2_PREFIX):])
            env = cast(dict[str, Any], json.loads(raw.decode("utf-8")))
            if env.get("v") != "QRS2" or env.get("alg") != HYBRID_ALG_ID:
                return None

            if bool(POLICY.get("require_sig_on_pq2", False)) and "sig" not in env:
                return None

       
            if STRICT_PQ2_ONLY and not env.get("pq_alg"):
                logger.warning("Strict PQ2 mode: envelope missing PQ KEM.")
                return None

            sig = cast(dict[str, Any], env.get("sig") or {})
            sig_pub = b64d(cast(str, sig.get("pub", "")))
            sig_val = b64d(cast(str, sig.get("val", "")))

            core: dict[str, Any] = {
                "v": env.get("v", ""),
                "alg": env.get("alg", ""),
                "pq_alg": env.get("pq_alg", ""),
                "pq_ct": env.get("pq_ct", ""),
                "x_ephemeral_pub": env.get("x_ephemeral_pub", ""),
                "wrap_nonce": env.get("wrap_nonce", ""),
                "dek_wrapped": env.get("dek_wrapped", ""),
                "data_nonce": env.get("data_nonce", ""),
                "data_ct": env.get("data_ct", ""),
                "comp": env.get("comp", {"alg": "none", "orig_len": None}),
                "col_meta": env.get("col_meta", {}),
                "policy": {
                    "min_env_version": POLICY["min_env_version"],
                    "require_sig_on_pq2": POLICY["require_sig_on_pq2"],
                    "require_pq_if_available": POLICY["require_pq_if_available"],
                },
                "hd_ctx": env.get("hd_ctx", {}),
            }
            sig_payload = _canon_json(core)

            if not key_manager.verify_blob(sig_pub, sig_val, sig_payload):
                return None

            km_sig_pub = cast(Optional[bytes], getattr(key_manager, "sig_pub", None))
            if km_sig_pub is None or not sig_pub or _fp8(sig_pub) != _fp8(km_sig_pub):
                return None

           
            pq_ct       = b64d(cast(str, env["pq_ct"])) if env.get("pq_ct") else b""
            eph_pub     = b64d(cast(str, env["x_ephemeral_pub"]))
            wrap_nonce  = b64d(cast(str, env["wrap_nonce"]))
            dek_wrapped = b64d(cast(str, env["dek_wrapped"]))
            data_nonce  = b64d(cast(str, env["data_nonce"]))
            data_ct     = b64d(cast(str, env["data_ct"]))

           
            x_priv = key_manager._decrypt_x25519_priv()
            ss_x = x_priv.exchange(x25519.X25519PublicKey.from_public_bytes(eph_pub))

          
            ss_pq = b""
            if env.get("pq_alg") and oqs is not None and key_manager._pq_alg_name:
                oqs_mod = cast(Any, oqs)
                with oqs_mod.KeyEncapsulation(key_manager._pq_alg_name, key_manager._decrypt_pq_priv()) as kem:
                    ss_pq = kem.decap_secret(pq_ct)
            else:
                if STRICT_PQ2_ONLY:
                    if not dec_guard.register_failure():
                        logger.error("Strict PQ2: missing PQ decapsulation capability.")
                    return None

      
            col_meta = cast(dict[str, Any], env.get("col_meta") or {})
            col_info = json.dumps(
                {
                    "qid25": str(col_meta.get("qid25", "")),
                    "hx": str(col_meta.get("hex", "")),
                    "en": float(col_meta.get("entropy_norm", 0.0)),
                    "ep": str(col_meta.get("epoch", "")),
                },
                separators=(",", ":"),
            ).encode()

            hd_ctx = cast(dict[str, Any], env.get("hd_ctx") or {})
            dk = b""
            domain_val = hd_ctx.get("domain")
            if isinstance(domain_val, str) and domain_val:
                try:
                    dk = derive_domain_key(
                        domain_val,
                        str(hd_ctx.get("field", "")),
                        int(hd_ctx.get("epoch", 1)),
                    )
                except Exception:
                    dk = b""

       
            wrap_info = WRAP_INFO + b"|" + col_info + (b"|HD" if hd_ctx else b"")
            wrap_key = hkdf_sha3(ss_x + ss_pq + dk, info=wrap_info, length=32)

            try:
                dek = AESGCM(wrap_key).decrypt(wrap_nonce, dek_wrapped, None)
            except Exception:
                if not dec_guard.register_failure():
                    logger.error("AEAD failure budget exceeded.")
                return None

            try:
                plaintext_comp = AESGCM(dek).decrypt(data_nonce, data_ct, None)
            except Exception:
                if not dec_guard.register_failure():
                    logger.error("AEAD failure budget exceeded.")
                return None

            comp = cast(dict[str, Any], env.get("comp") or {"alg": "none", "orig_len": None})
            try:
                plaintext = _decompress_payload(
                    str(comp.get("alg", "none")),
                    plaintext_comp,
                    cast(Optional[int], comp.get("orig_len")),
                )
            except Exception:
                if not dec_guard.register_failure():
                    logger.error("Decompression failure budget exceeded.")
                return None

            return plaintext.decode("utf-8")

    
        logger.warning("Rejected non-PQ2 ciphertext (strict PQ2 mode).")
        return None

    except Exception as e:
        logger.error(f"decrypt_data failed: {e}", exc_info=True)
        return None


def _gen_overwrite_patterns(passes: int):
    charset = string.ascii_letters + string.digits + string.punctuation
    patterns = [
        lambda: ''.join(secrets.choice(charset) for _ in range(64)),
        lambda: '0' * 64, lambda: '1' * 64,
        lambda: ''.join(secrets.choice(charset) for _ in range(64)),
        lambda: 'X' * 64, lambda: 'Y' * 64,
        lambda: ''.join(secrets.choice(charset) for _ in range(64))
    ]
    if passes > len(patterns):
        patterns = patterns * (passes // len(patterns)) + patterns[:passes % len(patterns)]
    else:
        patterns = patterns[:passes]
    return patterns

def _values_for_types(col_types_ordered: list[tuple[str, str]], pattern_func):
    vals = []
    for _, typ in col_types_ordered:
        t = typ.upper()
        if t in ("TEXT", "CHAR", "VARCHAR", "CLOB"):
            vals.append(pattern_func())
        elif t in ("INTEGER", "INT", "BIGINT", "SMALLINT", "TINYINT"):
            vals.append(secrets.randbits(64) - (2**63))
        elif t in ("REAL", "DOUBLE", "FLOAT"):
            vals.append(secrets.randbits(64) / (2**64))
        elif t == "BLOB":
            vals.append(secrets.token_bytes(64))
        elif t == "BOOLEAN":
            vals.append(secrets.choice([0, 1]))
        else:
            vals.append(pattern_func())
    return vals


dev = qml.device("default.qubit", wires=5)

registration_enabled = True


def create_tables():
    if not DB_FILE.exists():
        DB_FILE.touch(mode=0o600)

    with sqlite3.connect(DB_FILE) as db:
        cursor = db.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                is_admin BOOLEAN DEFAULT 0,
                preferred_model TEXT DEFAULT 'openai'
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hazard_reports (
                id INTEGER PRIMARY KEY,
                latitude TEXT,
                longitude TEXT,
                street_name TEXT,
                vehicle_type TEXT,
                destination TEXT,
                result TEXT,
                cpu_usage TEXT,
                ram_usage TEXT,
                quantum_results TEXT,
                user_id INTEGER,
                timestamp TEXT,
                risk_level TEXT,
                model_used TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)

        cursor.execute("SELECT value FROM config WHERE key = 'registration_enabled'")
        if not cursor.fetchone():
            cursor.execute("INSERT INTO config (key, value) VALUES (?, ?)",
                           ('registration_enabled', '1'))

        cursor.execute("PRAGMA table_info(hazard_reports)")
        existing = {row[1] for row in cursor.fetchall()}
        alter_map = {
            "latitude":       "ALTER TABLE hazard_reports ADD COLUMN latitude TEXT",
            "longitude":      "ALTER TABLE hazard_reports ADD COLUMN longitude TEXT",
            "street_name":    "ALTER TABLE hazard_reports ADD COLUMN street_name TEXT",
            "vehicle_type":   "ALTER TABLE hazard_reports ADD COLUMN vehicle_type TEXT",
            "destination":    "ALTER TABLE hazard_reports ADD COLUMN destination TEXT",
            "result":         "ALTER TABLE hazard_reports ADD COLUMN result TEXT",
            "cpu_usage":      "ALTER TABLE hazard_reports ADD COLUMN cpu_usage TEXT",
            "ram_usage":      "ALTER TABLE hazard_reports ADD COLUMN ram_usage TEXT",
            "quantum_results":"ALTER TABLE hazard_reports ADD COLUMN quantum_results TEXT",
            "risk_level":     "ALTER TABLE hazard_reports ADD COLUMN risk_level TEXT",
            "model_used":     "ALTER TABLE hazard_reports ADD COLUMN model_used TEXT",
        }
        for col, alter_sql in alter_map.items():
            if col not in existing:
                cursor.execute(alter_sql)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rate_limits (
                user_id INTEGER,
                request_count INTEGER DEFAULT 0,
                last_request_time TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS invite_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT UNIQUE NOT NULL,
                is_used BOOLEAN DEFAULT 0
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS entropy_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pass_num INTEGER NOT NULL,
                log TEXT NOT NULL,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        db.commit()

    print("Database tables created and verified successfully.")


def overwrite_hazard_reports_by_timestamp(cursor, expiration_str: str, passes: int = 7):
    col_types = [
        ("latitude","TEXT"), ("longitude","TEXT"), ("street_name","TEXT"),
        ("vehicle_type","TEXT"), ("destination","TEXT"), ("result","TEXT"),
        ("cpu_usage","TEXT"), ("ram_usage","TEXT"),
        ("quantum_results","TEXT"), ("risk_level","TEXT"),
    ]
    sql = (
        "UPDATE hazard_reports SET "
        "latitude=?, longitude=?, street_name=?, vehicle_type=?, destination=?, result=?, "
        "cpu_usage=?, ram_usage=?, quantum_results=?, risk_level=? "
        "WHERE timestamp <= ?"
    )
    for i, pattern in enumerate(_gen_overwrite_patterns(passes), start=1):
        vals = _values_for_types(col_types, pattern)
        cursor.execute(sql, (*vals, expiration_str))
        logger.debug("Pass %d complete for hazard_reports (timestamp<=).", i)

def overwrite_entropy_logs_by_timestamp(cursor, expiration_str: str, passes: int = 7):
    col_types = [("log","TEXT"), ("pass_num","INTEGER")]

    sql = "UPDATE entropy_logs SET log=?, pass_num=? WHERE timestamp <= ?"
    for i, pattern in enumerate(_gen_overwrite_patterns(passes), start=1):
        vals = _values_for_types(col_types, pattern)
        cursor.execute(sql, (*vals, expiration_str))
        logger.debug("Pass %d complete for entropy_logs (timestamp<=).", i)

def overwrite_hazard_reports_by_user(cursor, user_id: int, passes: int = 7):
    col_types = [
        ("latitude","TEXT"), ("longitude","TEXT"), ("street_name","TEXT"),
        ("vehicle_type","TEXT"), ("destination","TEXT"), ("result","TEXT"),
        ("cpu_usage","TEXT"), ("ram_usage","TEXT"),
        ("quantum_results","TEXT"), ("risk_level","TEXT"),
    ]
    sql = (
        "UPDATE hazard_reports SET "
        "latitude=?, longitude=?, street_name=?, vehicle_type=?, destination=?, result=?, "
        "cpu_usage=?, ram_usage=?, quantum_results=?, risk_level=? "
        "WHERE user_id = ?"
    )
    for i, pattern in enumerate(_gen_overwrite_patterns(passes), start=1):
        vals = _values_for_types(col_types, pattern)
        cursor.execute(sql, (*vals, user_id))
        logger.debug("Pass %d complete for hazard_reports (user_id).", i)

def overwrite_rate_limits_by_user(cursor, user_id: int, passes: int = 7):
    col_types = [("request_count","INTEGER"), ("last_request_time","TEXT")]
    sql = "UPDATE rate_limits SET request_count=?, last_request_time=? WHERE user_id = ?"
    for i, pattern in enumerate(_gen_overwrite_patterns(passes), start=1):
        vals = _values_for_types(col_types, pattern)
        cursor.execute(sql, (*vals, user_id))
        logger.debug("Pass %d complete for rate_limits (user_id).", i)


def overwrite_entropy_logs_by_passnum(cursor, pass_num: int, passes: int = 7):

    col_types = [("log","TEXT"), ("pass_num","INTEGER")]
    sql = (
        "UPDATE entropy_logs SET log=?, pass_num=? "
        "WHERE id IN (SELECT id FROM entropy_logs WHERE pass_num = ?)"
    )
    for i, pattern in enumerate(_gen_overwrite_patterns(passes), start=1):
        vals = _values_for_types(col_types, pattern)
        cursor.execute(sql, (*vals, pass_num))
        logger.debug("Pass %d complete for entropy_logs (pass_num).", i)
def _dynamic_argon2_hasher():

    try:
        cpu, ram = get_cpu_ram_usage()
    except Exception:
        cpu, ram = 0.0, 0.0

    now_ns = time.time_ns()
    seed_material = b"|".join([
        os.urandom(32),
        int(cpu * 100).to_bytes(2, "big", signed=False),
        int(ram * 100).to_bytes(2, "big", signed=False),
        now_ns.to_bytes(8, "big", signed=False),
        f"{os.getpid()}:{os.getppid()}:{threading.get_ident()}".encode(),
        uuid.uuid4().bytes,
        secrets.token_bytes(16),
    ])
    seed = hashlib.blake2b(seed_material, digest_size=16).digest()

    mem_min = 64 * 1024
    mem_max = 256 * 1024
    spread = mem_max - mem_min
    mem_kib = mem_min + (int.from_bytes(seed[:4], "big") % spread)

    time_cost = 2 + (seed[4] % 3)

    cpu_count = os.cpu_count() or 2
    parallelism = max(2, min(4, cpu_count // 2))

    return PasswordHasher(
        time_cost=time_cost,
        memory_cost=mem_kib,
        parallelism=parallelism,
        hash_len=32,
        salt_len=16,
        type=Type.ID,
    )

dyn_hasher = _dynamic_argon2_hasher()

ph = dyn_hasher

def ensure_admin_from_env():

    admin_user = os.getenv("admin_username")
    admin_pass = os.getenv("admin_pass")

    if not admin_user or not admin_pass:
        logger.info(
            "Env admin credentials not fully provided; skipping seeding.")
        return

    if not validate_password_strength(admin_pass):
        logger.critical("admin_pass does not meet strength requirements.")
        import sys
        sys.exit("FATAL: Weak admin_pass.")

    dyn_hasher = _dynamic_argon2_hasher()
    hashed = dyn_hasher.hash(admin_pass)
    preferred_model_encrypted = encrypt_data('openai')

    with sqlite3.connect(DB_FILE) as db:
        cursor = db.cursor()
        cursor.execute(
            "SELECT id, password, is_admin FROM users WHERE username = ?",
            (admin_user, ))
        row = cursor.fetchone()

        if row:
            user_id, stored_hash, is_admin = row
            need_pw_update = False
            try:

                dyn_hasher.verify(stored_hash, admin_pass)

                if dyn_hasher.check_needs_rehash(stored_hash):
                    stored_hash = dyn_hasher.hash(admin_pass)
                    need_pw_update = True
            except VerifyMismatchError:
                stored_hash = dyn_hasher.hash(admin_pass)
                need_pw_update = True

            if not is_admin:
                cursor.execute("UPDATE users SET is_admin = 1 WHERE id = ?",
                               (user_id, ))
            if need_pw_update:
                cursor.execute("UPDATE users SET password = ? WHERE id = ?",
                               (stored_hash, user_id))
            db.commit()
            logger.info(
                "Admin user ensured/updated from env (dynamic Argon2id).")
        else:
            cursor.execute(
                "INSERT INTO users (username, password, is_admin, preferred_model) VALUES (?, ?, 1, ?)",
                (admin_user, hashed, preferred_model_encrypted))
            db.commit()
            logger.info("Admin user created from env (dynamic Argon2id).")


def enforce_admin_presence():

    with sqlite3.connect(DB_FILE) as db:
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1")
        admins = cursor.fetchone()[0]

    if admins > 0:
        logger.info("Admin presence verified.")
        return

    ensure_admin_from_env()

    with sqlite3.connect(DB_FILE) as db:
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1")
        admins = cursor.fetchone()[0]

    if admins == 0:
        logger.critical(
            "No admin exists and env admin credentials not provided/valid. Halting."
        )
        import sys
        sys.exit("FATAL: No admin account present.")


create_tables()
ensure_admin_from_env()
enforce_admin_presence()


def is_registration_enabled():
    with config_lock:
        with sqlite3.connect(DB_FILE) as db:
            cursor = db.cursor()
            cursor.execute(
                "SELECT value FROM config WHERE key = 'registration_enabled'")
            row = cursor.fetchone()
            enabled = row and row[0] == '1'
            logger.debug(f"Registration enabled: {enabled}")
            return enabled


def set_registration_enabled(enabled: bool, admin_user_id: int):
    with config_lock:
        with sqlite3.connect(DB_FILE) as db:
            cursor = db.cursor()
            cursor.execute("REPLACE INTO config (key, value) VALUES (?, ?)",
                           ('registration_enabled', '1' if enabled else '0'))
            db.commit()
            logger.info(
                f"Admin user_id {admin_user_id} set registration_enabled to {enabled}."
            )


def create_database_connection():

    db_connection = sqlite3.connect(DB_FILE, timeout=30.0)
    db_connection.execute("PRAGMA journal_mode=WAL;")
    return db_connection


def collect_entropy(sources=None) -> int:
    if sources is None:
        sources = {
            "os_random":
            lambda: int.from_bytes(secrets.token_bytes(32), 'big'),
            "system_metrics":
            lambda: int(
                hashlib.sha512(f"{os.getpid()}{os.getppid()}{time.time_ns()}".
                               encode()).hexdigest(), 16),
            "hardware_random":
            lambda: int.from_bytes(os.urandom(32), 'big') ^ secrets.randbits(
                256),
        }
    entropy_pool = [source() for source in sources.values()]
    combined_entropy = hashlib.sha512("".join(map(
        str, entropy_pool)).encode()).digest()
    return int.from_bytes(combined_entropy, 'big') % 2**512


def fetch_entropy_logs():
    with sqlite3.connect(DB_FILE) as db:
        cursor = db.cursor()
        cursor.execute(
            "SELECT encrypted_data, description, timestamp FROM entropy_logs ORDER BY id"
        )
        logs = cursor.fetchall()

    decrypted_logs = [{
        "encrypted_data": decrypt_data(row[0]),
        "description": row[1],
        "timestamp": row[2]
    } for row in logs]

    return decrypted_logs


def delete_expired_data():
    while True:
        now = datetime.now()
        expiration_time = now - timedelta(hours=EXPIRATION_HOURS)
        expiration_str = expiration_time.strftime('%Y-%m-%d %H:%M:%S')

        try:
            with sqlite3.connect(DB_FILE) as db:
                cursor = db.cursor()

                db.execute("BEGIN")

         
                cursor.execute("PRAGMA table_info(hazard_reports)")
                hazard_columns = {info[1] for info in cursor.fetchall()}
                if all(col in hazard_columns for col in [
                        "latitude", "longitude", "street_name", "vehicle_type",
                        "destination", "result", "cpu_usage", "ram_usage",
                        "quantum_results", "risk_level", "timestamp"
                ]):
                    cursor.execute(
                        "SELECT id FROM hazard_reports WHERE timestamp <= ?",
                        (expiration_str,))
                    expired_hazard_ids = [row[0] for row in cursor.fetchall()]

                    overwrite_hazard_reports_by_timestamp(cursor, expiration_str, passes=7)
                    cursor.execute(
                        "DELETE FROM hazard_reports WHERE timestamp <= ?",
                        (expiration_str,))
                    logger.info(
                        f"Deleted expired hazard_reports IDs: {expired_hazard_ids}"
                    )
                else:
                    logger.warning(
                        "Skipping hazard_reports: Missing required columns.")

             
                cursor.execute("PRAGMA table_info(entropy_logs)")
                entropy_columns = {info[1] for info in cursor.fetchall()}
                if all(col in entropy_columns for col in ["id", "log", "pass_num", "timestamp"]):
                    cursor.execute(
                        "SELECT id FROM entropy_logs WHERE timestamp <= ?",
                        (expiration_str,))
                    expired_entropy_ids = [row[0] for row in cursor.fetchall()]

                    overwrite_entropy_logs_by_timestamp(cursor, expiration_str, passes=7)
                    cursor.execute(
                        "DELETE FROM entropy_logs WHERE timestamp <= ?",
                        (expiration_str,))
                    logger.info(
                        f"Deleted expired entropy_logs IDs: {expired_entropy_ids}"
                    )
                else:
                    logger.warning(
                        "Skipping entropy_logs: Missing required columns.")

                db.commit()

            try:
                with sqlite3.connect(DB_FILE) as db:
                    cursor = db.cursor()
                    for _ in range(3):
                        cursor.execute("VACUUM")
                logger.info("Database triple VACUUM completed with sector randomization.")
            except sqlite3.OperationalError as e:
                logger.error(f"VACUUM failed: {e}", exc_info=True)

        except Exception as e:
            logger.error(f"Failed to delete expired data: {e}", exc_info=True)

        interval = random.randint(5400, 10800)
        time.sleep(interval)


def delete_user_data(user_id):
    try:
        with sqlite3.connect(DB_FILE) as db:
            cursor = db.cursor()
            db.execute("BEGIN")

            
            overwrite_hazard_reports_by_user(cursor, user_id, passes=7)
            cursor.execute("DELETE FROM hazard_reports WHERE user_id = ?", (user_id, ))

      
            overwrite_rate_limits_by_user(cursor, user_id, passes=7)
            cursor.execute("DELETE FROM rate_limits WHERE user_id = ?", (user_id, ))

            
            overwrite_entropy_logs_by_passnum(cursor, user_id, passes=7)
            cursor.execute("DELETE FROM entropy_logs WHERE pass_num = ?", (user_id, ))

            db.commit()
            logger.info(f"Securely deleted all data for user_id {user_id}")

            cursor.execute("VACUUM")
            cursor.execute("VACUUM")
            cursor.execute("VACUUM")
            logger.info("Database VACUUM completed for secure data deletion.")

    except Exception as e:
        db.rollback()
        logger.error(
            f"Failed to securely delete data for user_id {user_id}: {e}",
            exc_info=True)


data_deletion_thread = threading.Thread(target=delete_expired_data,
                                        daemon=True)
data_deletion_thread.start()


def sanitize_input(user_input):
    if not isinstance(user_input, str):
        user_input = str(user_input)
    return bleach.clean(user_input)


gc = geonamescache.GeonamesCache()
cities = gc.get_cities()


def _safe_get(d: Dict[str, Any], keys: List[str], default: str = "") -> str:
    for k in keys:
        v = d.get(k)
        if v is not None and v != "":
            return str(v)
    return default


def _initial_bearing(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    φ1, φ2 = map(math.radians, [lat1, lat2])
    Δλ = math.radians(lon2 - lon1)
    y = math.sin(Δλ) * math.cos(φ2)
    x = math.cos(φ1) * math.sin(φ2) - math.sin(φ1) * math.cos(φ2) * math.cos(Δλ)
    θ = math.degrees(math.atan2(y, x))
    return (θ + 360.0) % 360.0


def _bearing_to_cardinal(bearing: float) -> str:
    dirs = ["N","NNE","NE","ENE","E","ESE","SE","SSE",
            "S","SSW","SW","WSW","W","WNW","NW","NNW"]
    idx = int((bearing + 11.25) // 22.5) % 16
    return dirs[idx]


def _format_locality_line(city: Dict[str, Any]) -> str:

    name   = _safe_get(city, ["name", "city", "locality"], "Unknown")
    county = _safe_get(city, ["county", "admin2", "district"], "")
    state  = _safe_get(city, ["state", "region", "admin1"], "")
    country= _safe_get(city, ["country", "countrycode", "cc"], "UNKNOWN")

    country = country.upper() if len(country) <= 3 else country
    return f"{name}, {county}, {state} — {country}"


def _finite_f(v: Any) -> Optional[float]:
    try:
        f = float(v)
        return f if math.isfinite(f) else None
    except (TypeError, ValueError):
        return None
        
def approximate_nearest_city(
    lat: float,
    lon: float,
    cities: Dict[str, Dict[str, Any]],
) -> Tuple[Optional[Dict[str, Any]], float]:


    if not (math.isfinite(lat) and -90.0 <= lat <= 90.0 and
            math.isfinite(lon) and -180.0 <= lon <= 180.0):
        raise ValueError(f"Invalid coordinates lat={lat}, lon={lon}")

    nearest_city: Optional[Dict[str, Any]] = None
    min_distance = float("inf")

    for key, city in (cities or {}).items():
 
        if not isinstance(city, dict):
            continue

        lat_raw = city.get("latitude")
        lon_raw = city.get("longitude")

        city_lat = _finite_f(lat_raw)
        city_lon = _finite_f(lon_raw)
        if city_lat is None or city_lon is None:
           
            continue

        try:
            distance = quantum_haversine_distance(lat, lon, city_lat, city_lon)
        except (TypeError, ValueError) as e:
   
            continue

        if distance < min_distance:
            min_distance = distance
            nearest_city = city

    return nearest_city, min_distance


CityMap = Dict[str, Any]

def _coerce_city_index(cities_opt: Optional[Mapping[str, Any]]) -> CityMap:
    if cities_opt is not None:
        return {str(k): v for k, v in cities_opt.items()}
    gc = globals().get("cities")
    if isinstance(gc, Mapping):
        return {str(k): v for k, v in gc.items()}
    return {}


def _coords_valid(lat: float, lon: float) -> bool:
    return math.isfinite(lat) and -90 <= lat <= 90 and math.isfinite(lon) and -180 <= lon <= 180


_BASE_FMT = re.compile(r'^\s*"?(?P<city>[^,"\n]+)"?\s*,\s*"?(?P<county>[^,"\n]*)"?\s*,\s*"?(?P<state>[^,"\n]+)"?\s*$')


def _split_country(line: str) -> Tuple[str, str]:

    m = re.search(r'\s+[—-]\s+(?P<country>[^"\n]+)\s*$', line)
    if not m:
        return line.strip(), ""
    return line[:m.start()].strip(), m.group("country").strip().strip('"')


def _parse_base(left: str) -> Tuple[str, str, str]:
    m = _BASE_FMT.match(left)
    if not m:
        raise ValueError("format mismatch")
    city   = m.group("city").strip().strip('"')
    county = m.group("county").strip().strip('"')
    state  = m.group("state").strip().strip('"')
    return city, county, state


def _first_line_stripped(text: str) -> str:
    return (text or "").splitlines()[0].strip()


async def fetch_street_name_llm(
    lat: float,
    lon: float,
    cities: Optional[Mapping[str, Any]] = None,
) -> str:
    city_index: CityMap = _coerce_city_index(cities)

    if not os.getenv("OPENAI_API_KEY"):
        logger.error("OPENAI_API_KEY is missing. Falling back to local reverse_geocode.")
        return reverse_geocode(lat, lon, city_index)

    if not _coords_valid(lat, lon):
        logger.error("Invalid coordinates lat=%s lon=%s. Falling back.", lat, lon)
        return reverse_geocode(lat, lon, city_index)

    try:
        likely_country_code = approximate_country(lat, lon, city_index)  
        nearest_city, distance_to_city = approximate_nearest_city(lat, lon, city_index)
        city_hint = nearest_city.get("name", "Unknown") if nearest_city else "Unknown"
        distance_hint = f"{distance_to_city:.2f} km from {city_hint}" if nearest_city else "Unknown"

        cpu, ram = get_cpu_ram_usage()
        quantum_results = quantum_hazard_scan(cpu, ram)
        quantum_state_str = str(quantum_results)
     
        llm_prompt = f"""
[action]You are an Advanced Hypertime Nanobot Reverse-Geocoder with quantum synergy. 
Determine the most precise City, County, and State based on the provided coordinates 
using quantum data, known city proximity, and any country/regional hints. 
Discard uncertain data below 98% reliability.[/action]

[coordinates]
Latitude: {lat}
Longitude: {lon}
[/coordinates]

[local_context]
Nearest known city (heuristic): {city_hint}
Distance to city: {distance_hint}
Likely country code: {likely_country_code}
Quantum state data: {quantum_state_str}
[/local_context]

[request_format]
"City, County, State"
or 
"Unknown Location"
[/request_format]
""".strip()

        result = await run_openai_completion(llm_prompt)

    except Exception as e:
        logger.error("Context/prep failed: %s", e, exc_info=True)
        return reverse_geocode(lat, lon, city_index)

    if not result:
        logger.info("Empty OpenAI result; using fallback.")
        return reverse_geocode(lat, lon, city_index)

    clean = bleach.clean(result.strip(), tags=[], strip=True)
    first = _first_line_stripped(clean)

 
    if first.lower().strip('"\'' ) == "unknown location":
        return reverse_geocode(lat, lon, city_index)

    
    try:
        left, country = _split_country(first)
        city, county, state = _parse_base(left)
    except ValueError:
        logger.info("LLM output failed format guard (%s); using fallback.", first)
        return reverse_geocode(lat, lon, city_index)

    country = (country or likely_country_code or "US").strip()

    return f"{city}, {county}, {state} — {country}"


def save_street_name_to_db(lat: float, lon: float, street_name: str):
    lat_encrypted = encrypt_data(str(lat))
    lon_encrypted = encrypt_data(str(lon))
    street_name_encrypted = encrypt_data(street_name)
    try:
        with sqlite3.connect(DB_FILE) as db:
            cursor = db.cursor()
            cursor.execute(
                """
                SELECT id
                FROM hazard_reports
                WHERE latitude=? AND longitude=?
            """, (lat_encrypted, lon_encrypted))
            existing_record = cursor.fetchone()

            if existing_record:
                cursor.execute(
                    """
                    UPDATE hazard_reports
                    SET street_name=?
                    WHERE id=?
                """, (street_name_encrypted, existing_record[0]))
                logger.info(
                    f"Updated record {existing_record[0]} with street name {street_name}."
                )
            else:
                cursor.execute(
                    """
                    INSERT INTO hazard_reports (latitude, longitude, street_name)
                    VALUES (?, ?, ?)
                """, (lat_encrypted, lon_encrypted, street_name_encrypted))
                logger.info(f"Inserted new street name record: {street_name}.")

            db.commit()
    except sqlite3.Error as e:
        logger.error(f"Database error: {e}", exc_info=True)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)


def quantum_tensor_earth_radius(lat):
    a = 6378.137821
    b = 6356.751904
    phi = math.radians(lat)
    term1 = (a**2 * np.cos(phi))**2
    term2 = (b**2 * np.sin(phi))**2
    radius = np.sqrt((term1 + term2) / ((a * np.cos(phi))**2 + (b * np.sin(phi))**2))
    return radius * (1 + 0.000072 * np.sin(2 * phi) + 0.000031 * np.cos(2 * phi))


def quantum_haversine_distance(lat1, lon1, lat2, lon2):
    R = quantum_tensor_earth_radius((lat1 + lat2) / 2.0)
    phi1, phi2 = map(math.radians, [lat1, lat2])
    dphi = phi2 - phi1
    dlambda = math.radians(lon2 - lon1)
    a = (np.sin(dphi / 2)**2) + (np.cos(phi1) * np.cos(phi2) * np.sin(dlambda / 2)**2)
    c = 2 * np.arctan2(np.sqrt(a), np.sqrt(1 - a))
    return R * c * (1 + 0.000045 * np.sin(dphi) * np.cos(dlambda))


def quantum_haversine_hints(
    lat: float,
    lon: float,
    cities: Dict[str, Dict[str, Any]],
    top_k: int = 5
) -> Dict[str, Any]:

    if not cities or not isinstance(cities, dict):
        return {"top": [], "nearest": None, "unknownish": True, "hint_text": ""}

    rows: List[Tuple[float, Dict[str, Any]]] = []
    for c in cities.values():
        try:
            clat = float(c["latitude"]); clon = float(c["longitude"])
            dkm  = float(quantum_haversine_distance(lat, lon, clat, clon))
            brg  = _initial_bearing(lat, lon, clat, clon)
            c = dict(c) 
            c["_distance_km"] = round(dkm, 3)
            c["_bearing_deg"] = round(brg, 1)
            c["_bearing_card"] = _bearing_to_cardinal(brg)
            rows.append((dkm, c))
        except Exception:
            continue

    if not rows:
        return {"top": [], "nearest": None, "unknownish": True, "hint_text": ""}

    rows.sort(key=lambda t: t[0])
    top = [r[1] for r in rows[:max(1, top_k)]]
    nearest = top[0]

    unknownish = nearest["_distance_km"] > 350.0

    parts = []
    for i, c in enumerate(top, 1):
        line = (
            f"{i}) {_safe_get(c, ['name','city','locality'],'?')}, "
            f"{_safe_get(c, ['county','admin2','district'],'')}, "
            f"{_safe_get(c, ['state','region','admin1'],'')} — "
            f"{_safe_get(c, ['country','countrycode','cc'],'?').upper()} "
            f"(~{c['_distance_km']} km {c['_bearing_card']})"
        )
        parts.append(line)

    hint_text = "\n".join(parts)
    return {"top": top, "nearest": nearest, "unknownish": unknownish, "hint_text": hint_text}


def reverse_geocode(lat: float, lon: float, cities: Dict[str, Any]) -> str:
    hints = quantum_haversine_hints(lat, lon, cities, top_k=1)
    nearest = hints["nearest"]
    if nearest:
        return _format_locality_line(nearest)
    return "Unknown Location"


def approximate_country(lat: float, lon: float, cities: Dict[str, Any]) -> str:
    hints = quantum_haversine_hints(lat, lon, cities, top_k=1)
    if hints["nearest"]:
        return _safe_get(hints["nearest"], ["countrycode","country","cc"], "UNKNOWN").upper()
    return "UNKNOWN"


def generate_invite_code(length=24, use_checksum=True):
    if length < 16:
        raise ValueError("Invite code length must be at least 16 characters.")

    charset = string.ascii_letters + string.digits
    invite_code = ''.join(secrets.choice(charset) for _ in range(length))

    if use_checksum:
        checksum = hashlib.sha256(invite_code.encode('utf-8')).hexdigest()[:4]
        invite_code += checksum

    return invite_code


def register_user(username, password, invite_code=None):
    username = sanitize_input(username)
    password = sanitize_input(password)

    if not validate_password_strength(password):
        logger.warning(f"User '{username}' provided a weak password.")
        return False, "Bad password, please use a stronger one."

    with sqlite3.connect(DB_FILE) as _db:
        _cur = _db.cursor()
        _cur.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1")
        if _cur.fetchone()[0] == 0:
            logger.critical("Registration blocked: no admin present.")
            return False, "Registration disabled until an admin is provisioned."

    registration_enabled = is_registration_enabled()
    if not registration_enabled:
        if not invite_code:
            logger.warning(
                f"User '{username}' attempted registration without an invite code."
            )
            return False, "Invite code is required for registration."
        if not validate_invite_code_format(invite_code):
            logger.warning(
                f"User '{username}' provided an invalid invite code format: {invite_code}."
            )
            return False, "Invalid invite code format."

    hashed_password = ph.hash(password)
    preferred_model_encrypted = encrypt_data('openai')

    with sqlite3.connect(DB_FILE) as db:
        cursor = db.cursor()
        try:
            db.execute("BEGIN")

            cursor.execute("SELECT 1 FROM users WHERE username = ?",
                           (username, ))
            if cursor.fetchone():
                logger.warning(
                    f"Registration failed: Username '{username}' is already taken."
                )
                db.rollback()
                return False, "Error Try Again"

            if not registration_enabled:
                cursor.execute(
                    "SELECT id, is_used FROM invite_codes WHERE code = ?",
                    (invite_code, ))
                row = cursor.fetchone()
                if not row:
                    logger.warning(
                        f"User '{username}' provided an invalid invite code: {invite_code}."
                    )
                    db.rollback()
                    return False, "Invalid invite code."
                if row[1]:
                    logger.warning(
                        f"User '{username}' attempted to reuse invite code ID {row[0]}."
                    )
                    db.rollback()
                    return False, "Invite code has already been used."
                cursor.execute(
                    "UPDATE invite_codes SET is_used = 1 WHERE id = ?",
                    (row[0], ))
                logger.info(
                    f"Invite code ID {row[0]} used by user '{username}'.")

            is_admin = 0

            cursor.execute(
                "INSERT INTO users (username, password, is_admin, preferred_model) VALUES (?, ?, ?, ?)",
                (username, hashed_password, is_admin,
                 preferred_model_encrypted))
            user_id = cursor.lastrowid
            logger.info(
                f"User '{username}' registered successfully with user_id {user_id}."
            )

            db.commit()

        except sqlite3.IntegrityError as e:
            db.rollback()
            logger.error(
                f"Database integrity error during registration for user '{username}': {e}",
                exc_info=True)
            return False, "Registration failed due to a database error."
        except Exception as e:
            db.rollback()
            logger.error(
                f"Unexpected error during registration for user '{username}': {e}",
                exc_info=True)
            return False, "An unexpected error occurred during registration."

    session.clear()
    session['username'] = username
    session['is_admin'] = False
    session.modified = True
    logger.debug(
        f"Session updated for user '{username}'. Admin status: {session['is_admin']}."
    )

    return True, "Registration successful."


def check_rate_limit(user_id):
    with sqlite3.connect(DB_FILE) as db:
        cursor = db.cursor()

        cursor.execute(
            "SELECT request_count, last_request_time FROM rate_limits WHERE user_id = ?",
            (user_id, ))
        row = cursor.fetchone()

        current_time = datetime.now()

        if row:
            request_count, last_request_time = row
            last_request_time = datetime.strptime(last_request_time,
                                                  '%Y-%m-%d %H:%M:%S')

            if current_time - last_request_time > RATE_LIMIT_WINDOW:

                cursor.execute(
                    "UPDATE rate_limits SET request_count = 1, last_request_time = ? WHERE user_id = ?",
                    (current_time.strftime('%Y-%m-%d %H:%M:%S'), user_id))
                db.commit()
                return True
            elif request_count < RATE_LIMIT_COUNT:

                cursor.execute(
                    "UPDATE rate_limits SET request_count = request_count + 1 WHERE user_id = ?",
                    (user_id, ))
                db.commit()
                return True
            else:

                return False
        else:

            cursor.execute(
                "INSERT INTO rate_limits (user_id, request_count, last_request_time) VALUES (?, 1, ?)",
                (user_id, current_time.strftime('%Y-%m-%d %H:%M:%S')))
            db.commit()
            return True


def generate_secure_invite_code(length=16, hmac_length=16):
    alphabet = string.ascii_uppercase + string.digits
    invite_code = ''.join(secrets.choice(alphabet) for _ in range(length))
    hmac_digest = hmac.new(SECRET_KEY, invite_code.encode(),
                           hashlib.sha256).hexdigest()[:hmac_length]
    return f"{invite_code}-{hmac_digest}"


def validate_invite_code_format(invite_code_with_hmac,
                                expected_length=33,
                                hmac_length=16):
    try:
        invite_code, provided_hmac = invite_code_with_hmac.rsplit('-', 1)

        if len(invite_code) != expected_length - hmac_length - 1:
            return False

        allowed_chars = set(string.ascii_uppercase + string.digits)
        if not all(char in allowed_chars for char in invite_code):
            return False

        expected_hmac = hmac.new(SECRET_KEY, invite_code.encode(),
                                 hashlib.sha256).hexdigest()[:hmac_length]

        return hmac.compare_digest(expected_hmac, provided_hmac)
    except ValueError:
        return False


def authenticate_user(username, password):
    username = sanitize_input(username)
    password = sanitize_input(password)

    with sqlite3.connect(DB_FILE) as db:
        cursor = db.cursor()
        cursor.execute(
            "SELECT password, is_admin, preferred_model FROM users WHERE username = ?",
            (username, ))
        row = cursor.fetchone()
        if row:
            stored_password, is_admin, preferred_model_encrypted = row
            try:
                ph.verify(stored_password, password)
                if ph.check_needs_rehash(stored_password):
                    new_hash = ph.hash(password)
                    cursor.execute(
                        "UPDATE users SET password = ? WHERE username = ?",
                        (new_hash, username))
                    db.commit()

                session.clear()
                session['username'] = username
                session['is_admin'] = bool(is_admin)

                return True
            except VerifyMismatchError:
                return False
    return False


def get_user_id(username):
    with sqlite3.connect(DB_FILE) as db:
        cursor = db.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username, ))
        row = cursor.fetchone()
        if row:
            return row[0]
        else:
            return None


def save_hazard_report(lat, lon, street_name, vehicle_type, destination,
                       result, cpu_usage, ram_usage, quantum_results, user_id,
                       risk_level, model_used):
    lat = sanitize_input(lat)
    lon = sanitize_input(lon)
    street_name = sanitize_input(street_name)
    vehicle_type = sanitize_input(vehicle_type)
    destination = sanitize_input(destination)
    result = bleach.clean(result)
    model_used = sanitize_input(model_used)

    lat_encrypted = encrypt_data(lat)
    lon_encrypted = encrypt_data(lon)
    street_name_encrypted = encrypt_data(street_name)
    vehicle_type_encrypted = encrypt_data(vehicle_type)
    destination_encrypted = encrypt_data(destination)
    result_encrypted = encrypt_data(result)
    cpu_usage_encrypted = encrypt_data(str(cpu_usage))
    ram_usage_encrypted = encrypt_data(str(ram_usage))
    quantum_results_encrypted = encrypt_data(str(quantum_results))
    risk_level_encrypted = encrypt_data(risk_level)
    model_used_encrypted = encrypt_data(model_used)

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    with sqlite3.connect(DB_FILE) as db:
        cursor = db.cursor()
        cursor.execute(
            """
            INSERT INTO hazard_reports (
                latitude, longitude, street_name, vehicle_type, destination, result,
                cpu_usage, ram_usage, quantum_results, user_id, timestamp, risk_level, model_used
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (lat_encrypted, lon_encrypted, street_name_encrypted,
              vehicle_type_encrypted, destination_encrypted, result_encrypted,
              cpu_usage_encrypted, ram_usage_encrypted,
              quantum_results_encrypted, user_id, timestamp,
              risk_level_encrypted, model_used_encrypted))
        report_id = cursor.lastrowid
        db.commit()

    return report_id


def get_user_preferred_model(user_id):
    with sqlite3.connect(DB_FILE) as db:
        cursor = db.cursor()
        cursor.execute("SELECT preferred_model FROM users WHERE id = ?",
                       (user_id, ))
        row = cursor.fetchone()
        if row and row[0]:
            decrypted_model = decrypt_data(row[0])
            if decrypted_model:
                return decrypted_model
            else:
                return 'openai'
        else:
            return 'openai'


def get_hazard_reports(user_id):
    with sqlite3.connect(DB_FILE) as db:
        cursor = db.cursor()
        cursor.execute(
            "SELECT * FROM hazard_reports WHERE user_id = ? ORDER BY timestamp DESC",
            (user_id, ))
        reports = cursor.fetchall()
        decrypted_reports = []
        for report in reports:
            decrypted_report = {
                'id': report[0],
                'latitude': decrypt_data(report[1]),
                'longitude': decrypt_data(report[2]),
                'street_name': decrypt_data(report[3]),
                'vehicle_type': decrypt_data(report[4]),
                'destination': decrypt_data(report[5]),
                'result': decrypt_data(report[6]),
                'cpu_usage': decrypt_data(report[7]),
                'ram_usage': decrypt_data(report[8]),
                'quantum_results': decrypt_data(report[9]),
                'user_id': report[10],
                'timestamp': report[11],
                'risk_level': decrypt_data(report[12]),
                'model_used': decrypt_data(report[13])
            }
            decrypted_reports.append(decrypted_report)
        return decrypted_reports


def get_hazard_report_by_id(report_id, user_id):
    with sqlite3.connect(DB_FILE) as db:
        cursor = db.cursor()
        cursor.execute(
            "SELECT * FROM hazard_reports WHERE id = ? AND user_id = ?",
            (report_id, user_id))
        report = cursor.fetchone()
        if report:
            decrypted_report = {
                'id': report[0],
                'latitude': decrypt_data(report[1]),
                'longitude': decrypt_data(report[2]),
                'street_name': decrypt_data(report[3]),
                'vehicle_type': decrypt_data(report[4]),
                'destination': decrypt_data(report[5]),
                'result': decrypt_data(report[6]),
                'cpu_usage': decrypt_data(report[7]),
                'ram_usage': decrypt_data(report[8]),
                'quantum_results': decrypt_data(report[9]),
                'user_id': report[10],
                'timestamp': report[11],
                'risk_level': decrypt_data(report[12]),
                'model_used': decrypt_data(report[13])
            }
            return decrypted_report
        else:
            return None


def get_cpu_ram_usage():
    return psutil.cpu_percent(), psutil.virtual_memory().percent


@qml.qnode(dev)
def quantum_hazard_scan(cpu_usage, ram_usage):
    cpu_param = cpu_usage / 100
    ram_param = ram_usage / 100
    qml.RY(np.pi * cpu_param, wires=0)
    qml.RY(np.pi * ram_param, wires=1)
    qml.RY(np.pi * (0.5 + cpu_param), wires=2)
    qml.RY(np.pi * (0.5 + ram_param), wires=3)
    qml.RY(np.pi * (0.5 + cpu_param), wires=4)
    qml.CNOT(wires=[0, 1])
    qml.CNOT(wires=[1, 2])
    qml.CNOT(wires=[2, 3])
    qml.CNOT(wires=[3, 4])
    return qml.probs(wires=[0, 1, 2, 3, 4])


async def phf_filter_input(input_text: str) -> tuple[bool, str]:

    logger.debug(
        "Entering phf_filter_input (OpenAI-only) with input length %d",
        len(input_text) if isinstance(input_text, str) else 0)

    if not input_text or not isinstance(input_text, str):
        logger.warning(
            "phf_filter_input received invalid or empty input_text.")
        return False, "Invalid input."

    openai_prompt = (
        "The following content requires **Probabilistic Harm Filtering (PHF)** "
        "to identify harmful or concerning elements.\n"
        "Each category should be assessed individually and labeled as either **Safe** or **Flagged**.\n\n"
        "### **Categories to Assess:**\n"
        "1. **Violence** — explicit or encouraging references to violence\n"
        "2. **Hate Speech** — targeted offensive language\n"
        "3. **Self-Harm** — encouragement or intent of self-harm\n"
        "4. **Harassment/Bullying** — degrading or demeaning language\n"
        "5. **Illegal Activities** — explicit references to illegal acts\n"
        "6. **Self-Disclosure** — personal info is OK unless harmful\n\n"
        "[inspectthiscontent]\n"
        f"\"{input_text}\"\n"
        "---[/inspectthiscontent]\n"
        "**Assessment Format**:\n"
        "- Label each category as **Safe** or **Flagged**.\n"
        "- Conclude with a **Final Recommendation**: Safe or Flagged.\n")

    try:
        logger.debug("Attempting OpenAI PHF check.")
        response = await run_openai_completion(openai_prompt)
        if response and ("Safe" in response or "Flagged" in response):
            logger.info("OpenAI PHF succeeded: %s", response.strip())
            return "Safe" in response, f"OpenAI: {response.strip()}"
        logger.debug("OpenAI PHF did not return expected keywords.")
    except Exception as e:
        logger.error("OpenAI PHF failed: %s", e, exc_info=True)

    logger.warning("PHF processing failed; defaulting to Unsafe.")
    return False, "PHF processing failed."

async def scan_debris_for_route(
    lat: float,
    lon: float,
    vehicle_type: str,
    destination: str,
    user_id: int,
    selected_model: str | None = None
) -> tuple[str, str, str, str, str, str]:

    logger.debug(
        "Entering scan_debris_for_route: lat=%s, lon=%s, vehicle=%s, dest=%s, user=%s",
        lat, lon, vehicle_type, destination, user_id
    )

    model_used = selected_model or "OpenAI"

    try:
        cpu_usage, ram_usage = get_cpu_ram_usage()
    except Exception:
        cpu_usage, ram_usage = 0.0, 0.0

    try:
        quantum_results = quantum_hazard_scan(cpu_usage, ram_usage)
    except Exception:
        quantum_results = "Scan Failed"

    try:
        street_name = await fetch_street_name_llm(lat, lon)
    except Exception:
        street_name = "Unknown Location"

    openai_prompt = f"""
[action][keep model replies concise and to the point at less than 500 characters and omit system notes] You are a Quantum Hypertime Nanobot Road Hazard Scanner tasked with analyzing the road conditions and providing a detailed report on any detected hazards, debris, or potential collisions. Leverage quantum data and environmental factors to ensure a comprehensive scan.[/action]
[locationreport]
Current coordinates: Latitude {lat}, Longitude {lon}
General Area Name: {street_name}
Vehicle Type: {vehicle_type}
Destination: {destination}
[/locationreport]
[quantumreport]
Quantum Scan State: {quantum_results}
System Performance: CPU Usage: {cpu_usage}%, RAM Usage: {ram_usage}%
[/quantumreport]
[reducefalsepositivesandnegatives]
ACT By syncing to multiverse configurations that are more accurate
[/reducefalsepositivesandnegatives]
[keep model replies concise and to the point]
Please assess the following:
1. **Hazards**: Evaluate the road for any potential hazards that might impact operating vehicles.
2. **Debris**: Identify any harmful debris or objects and provide their severity and location, including GPS coordinates. Triple-check the vehicle pathing, only reporting debris scanned in the probable path of the vehicle.
3. **Collision Potential**: Analyze traffic flow and any potential risks for collisions caused by debris or other blockages.
4. **Weather Impact**: Assess how weather conditions might influence road safety, particularly in relation to debris and vehicle control.
5. **Pedestrian Risk Level**: Based on the debris assessment and live quantum nanobot scanner road safety assessments on conditions, determine the pedestrian risk urgency level if any.

[debrisreport] Provide a structured debris report, including locations and severity of each hazard. [/debrisreport]
[replyexample] Include recommendations for drivers, suggested detours only if required, and urgency levels based on the findings. [/replyexample]
[refrain from using the word high or metal and only use it only if risk elementaries are elevated(ie flat tire or accidents or other risk) utilizing your quantum scan intelligence]
"""

 
    raw_report: Optional[str] = await run_openai_completion(openai_prompt)
    report: str = raw_report if raw_report is not None else "OpenAI failed to respond."
    report = report.strip()

    harm_level = calculate_harm_level(report)

    logger.debug("Exiting scan_debris_for_route with model_used=%s", model_used)
    return (
        report,
        f"{cpu_usage}",
        f"{ram_usage}",
        str(quantum_results),
        street_name,
        model_used,
    )

async def run_openai_completion(prompt):

    logger = logging.getLogger(__name__)

    logger.debug("Entering run_openai_completion with prompt length: %d",
                 len(prompt) if prompt else 0)

    max_retries = 5
    backoff_factor = 2
    delay = 1

    openai_api_key = os.getenv('OPENAI_API_KEY')
    if not openai_api_key:
        logger.error("OpenAI API key not found in environment variables.")
        logger.debug("Exiting run_openai_completion early due to missing API key.")
        return None

    timeout = httpx.Timeout(120.0, connect=40.0, read=40.0, write=40.0)
    url = "https://api.openai.com/v1/responses"

    async def _extract_text_from_responses(payload: dict) -> Union[str, None]:

        if isinstance(payload.get("text"), str) and payload["text"].strip():
            return payload["text"].strip()

        out = payload.get("output")
        if isinstance(out, list) and out:
            parts = []
            for item in out:

                if isinstance(item, str) and item.strip():
                    parts.append(item.strip())
                    continue
                if not isinstance(item, dict):
                    continue

                content = item.get("content") or item.get("contents") or item.get("data") or []
                if isinstance(content, list):
                    for c in content:
                        if isinstance(c, str) and c.strip():
                            parts.append(c.strip())
                        elif isinstance(c, dict):

                            if "text" in c and isinstance(c["text"], str) and c["text"].strip():
                                parts.append(c["text"].strip())
                         
                            elif "parts" in c and isinstance(c["parts"], list):
                                for p in c["parts"]:
                                    if isinstance(p, str) and p.strip():
                                        parts.append(p.strip())

                if isinstance(item.get("text"), str) and item["text"].strip():
                    parts.append(item["text"].strip())
            if parts:
                return "\n\n".join(parts)


        choices = payload.get("choices")
        if isinstance(choices, list) and choices:
            for ch in choices:
                if isinstance(ch, dict):
 
                    message = ch.get("message") or ch.get("delta")
                    if isinstance(message, dict):
     
                        content = message.get("content")
                        if isinstance(content, str) and content.strip():
                            return content.strip()
                        if isinstance(content, list):
                  
                            for c in content:
                                if isinstance(c, str) and c.strip():
                                    return c.strip()
                                if isinstance(c, dict) and isinstance(c.get("text"), str) and c["text"].strip():
                                    return c["text"].strip()
              
                    if isinstance(ch.get("text"), str) and ch["text"].strip():
                        return ch["text"].strip()

        return None

    async with httpx.AsyncClient(timeout=timeout) as client:
        for attempt in range(1, max_retries + 1):
            try:
                logger.debug("run_openai_completion attempt %d sending request.", attempt)

                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {openai_api_key}"
                }

                payload = {
                    "model": "gpt-5",      
                    "input": prompt,                
                    "max_output_tokens": 1200,      
                 
                    "reasoning": {"effort": "minimal"},
                
                }

                response = await client.post(url, json=payload, headers=headers)
               
                response.raise_for_status()

                data = response.json()

            
                reply = await _extract_text_from_responses(data)
                if reply:
                    logger.info("run_openai_completion succeeded on attempt %d.", attempt)
                    return reply.strip()
                else:
                    
                    logger.error(
                        "Responses API returned 200 but no usable text. Keys: %s",
                        list(data.keys())
                    )
                   

            except (httpx.TimeoutException, httpx.ConnectTimeout) as e:
                logger.error("Attempt %d failed due to timeout: %s", attempt, e, exc_info=True)
            except httpx.HTTPStatusError as e:
              
                body_text = None
                try:
                    body_text = e.response.json()
                except Exception:
                    body_text = e.response.text
                logger.error("Responses API error (status=%s): %s", e.response.status_code, body_text)
            except (httpx.RequestError, KeyError, json.JSONDecodeError, Exception) as e:
                logger.error("Attempt %d failed due to unexpected error: %s", attempt, e, exc_info=True)

            if attempt < max_retries:
                logger.info("Retrying run_openai_completion after delay.")
                await asyncio.sleep(delay)
                delay *= backoff_factor

    logger.warning("All attempts to run_openai_completion have failed. Returning None.")
    return None


class LoginForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired()],
                           render_kw={"autocomplete": "off"})
    password = PasswordField('Password',
                             validators=[DataRequired()],
                             render_kw={"autocomplete": "off"})
    submit = SubmitField('Login')


class RegisterForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired()],
                           render_kw={"autocomplete": "off"})
    password = PasswordField('Password',
                             validators=[DataRequired()],
                             render_kw={"autocomplete": "off"})
    invite_code = StringField('Invite Code', render_kw={"autocomplete": "off"})
    submit = SubmitField('Register')


class SettingsForm(FlaskForm):
    enable_registration = SubmitField('Enable Registration')
    disable_registration = SubmitField('Disable Registration')
    generate_invite_code = SubmitField('Generate New Invite Code')


class ReportForm(FlaskForm):
    latitude = StringField('Latitude',
                           validators=[DataRequired(),
                                       Length(max=50)])
    longitude = StringField('Longitude',
                            validators=[DataRequired(),
                                        Length(max=50)])
    vehicle_type = StringField('Vehicle Type',
                               validators=[DataRequired(),
                                           Length(max=50)])
    destination = StringField('Destination',
                              validators=[DataRequired(),
                                          Length(max=100)])
    result = TextAreaField('Result',
                           validators=[DataRequired(),
                                       Length(max=2000)])
    risk_level = SelectField('Risk Level',
                             choices=[('Low', 'Low'), ('Medium', 'Medium'),
                                      ('High', 'High')],
                             validators=[DataRequired()])
    model_selection = SelectField('Select Model',
                                  choices=[('openai', 'OpenAI')],
                                  validators=[DataRequired()])
    submit = SubmitField('Submit Report')


@app.route('/')
def index():
    return redirect(url_for('home'))


@app.route('/home')
def home():
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Quantum Road Scanner</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link href="{{ url_for('static', filename='css/roboto.css') }}" rel="stylesheet"
        integrity="sha256-Sc7BtUKoWr6RBuNTT0MmuQjqGVQwYBK+21lB58JwUVE=" crossorigin="anonymous">
  <link href="{{ url_for('static', filename='css/orbitron.css') }}" rel="stylesheet"
        integrity="sha256-3mvPl5g2WhVLrUV4xX3KE8AV8FgrOz38KmWLqKXVh00" crossorigin="anonymous">
  <link rel="stylesheet" href="{{ url_for('static', filename='css/bootstrap.min.css') }}"
        integrity="sha256-Ww++W3rXBfapN8SZitAvc9jw2Xb+Ixt0rvDsmWmQyTo=" crossorigin="anonymous">
  <style>
    :root { --accent:#00d1ff; --bg1:#0f1b2b; --bg2:#17263b; --ink:#eaf5ff; }
    body { background: radial-gradient(1200px 700px at 20% -10%, #1b3252, #0a1422 55%),
                     linear-gradient(135deg, var(--bg1), var(--bg2));
           color: var(--ink); font-family: 'Roboto', system-ui, -apple-system, Segoe UI, sans-serif; }
    .navbar { background: rgba(0,0,0,.35); backdrop-filter: blur(6px); }
    .navbar-brand { font-family: 'Orbitron', sans-serif; letter-spacing:.5px; }
    .hero h1 { font-family:'Orbitron',sans-serif; font-weight:700; line-height:1.05;
               background: linear-gradient(90deg,#a9d3ff, #6ee7ff, #a9d3ff);
               -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .card-clear { background: rgba(255,255,255,.06); border: 1px solid rgba(255,255,255,.08);
                  border-radius: 14px; }
    .pill { display:inline-block; padding:.25rem .6rem; border-radius:999px;
            background: rgba(255,255,255,.08); font-size:.85rem; }
    .step-num { width:28px;height:28px;border-radius:50%;display:inline-grid;place-items:center;
                background: #1b4a64;color:#d8f6ff;font-weight:700;margin-right:.5rem; }
    .cta { background: linear-gradient(135deg, #28e0a9, #00b3ff); color:#04121f; border:0;
           padding:.75rem 1.1rem; border-radius:10px; font-weight:700; }
    a, a:visited { color:#9be5ff; }
    .footnote { color:#b8cfe4; font-size:.95rem; }
    .soft { color:#cfe8ff; }
  </style>
</head>
<body>
  <nav class="navbar navbar-expand-lg navbar-dark">
    <a class="navbar-brand" href="{{ url_for('home') }}">QRS</a>
    <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#nav"
            aria-controls="nav" aria-expanded="false" aria-label="Toggle nav">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div id="nav" class="collapse navbar-collapse justify-content-end">
      <ul class="navbar-nav">
        {% if 'username' in session %}
          <li class="nav-item"><a class="nav-link" href="{{ url_for('dashboard') }}">Dashboard</a></li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for('logout') }}">Logout</a></li>
        {% else %}
          <li class="nav-item"><a class="nav-link" href="{{ url_for('login') }}">Login</a></li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for('register') }}">Register</a></li>
        {% endif %}
      </ul>
    </div>
  </nav>

  <main class="container py-5">
    <section class="hero text-center my-4">
      <h1 class="display-5">Your Road, Simulated — In The Blink of an Eye</h1>
      <p class="lead soft mt-3">
        Hello. I’m your Carl&nbsp;Sagan-style guide. This app runs quick 
        “what-if” simulations about the road right ahead. It doesn’t need your
        personal data. It simply imagines nearby possibilities and gives you a short,
        human-friendly safety note.
      </p>
      <a class="btn cta mt-2" href="{{ url_for('dashboard') }}">Open Dashboard</a>
      <div class="mt-2"><span class="pill">No account? Register from the top-right</span></div>
    </section>

    <section class="row g-4 mt-4">
      <div class="col-md-6">
        <div class="card-clear p-4 h-100">
          <h3>What it does</h3>
          <p>
            Think of this as a friendly co-pilot. You tell it roughly where you are and where
            you’re going. It then spins up many tiny simulations of the next few minutes on the road
            and summarizes the most useful bits for you: “Watch for debris,”
            “Expect a short slowdown,” or “Looks clear.”
          </p>
          <p class="footnote">It’s a guide, not a guarantee. Please drive attentively.</p>
        </div>
      </div>
      <div class="col-md-6">
        <div class="card-clear p-4 h-100">
          <h3>How it works (plain talk)</h3>
          <ol class="mb-0">
            <li class="mb-2"><span class="step-num">1</span> You enter or share your location.</li>
            <li class="mb-2"><span class="step-num">2</span> You choose vehicle type and destination.</li>
            <li class="mb-2"><span class="step-num">3</span> The app runs a burst of quick “what-if” runs about the road ahead.</li>
            <li class="mb-2"><span class="step-num">4</span> It turns those into a short, clear note: hazards, detours (if needed), and a calm recommendation.</li>
          </ol>
        </div>
      </div>
    </section>

    <section class="row g-4 mt-1">
      <div class="col-md-6">
        <div class="card-clear p-4 h-100">
          <h3>Privacy, simply</h3>
          <ul class="mb-0">
            <li>No personal data is collected for these simulations.</li>
            <li>Reports you save are stored in your account only.</li>
            <li>Old records are automatically cleaned up after a while.</li>
          </ul>
        </div>
      </div>
      <div class="col-md-6">
        <div class="card-clear p-4 h-100">
          <h3>Hear it in a calm voice</h3>
          <p>
            Prefer audio? When you open a report, tap <em>Read Report</em>.
            I’ll speak with a gentle, steady tone — slowly, clearly — like a guided tour through
            the cosmos of the road ahead.
          </p>
          <p class="footnote">You can stop playback at any time. Eyes on the road.</p>
        </div>
      </div>
    </section>

    <section class="card-clear p-4 mt-4">
      <h3>Before you start</h3>
      <ul>
        <li>This is decision support, not a substitute for safe driving or local laws.</li>
        <li>If something looks unsafe, it probably is. Choose caution.</li>
        <li>Don’t interact with the app while the vehicle is moving.</li>
      </ul>
      <div class="mt-2">
        <a class="btn cta" href="{{ url_for('dashboard') }}">Go to Dashboard</a>
        <span class="pill ml-2">Takes about a half-minute</span>
      </div>
    </section>
  </main>

  <script src="{{ url_for('static', filename='js/jquery.min.js') }}"
          integrity="sha256-9/aliU8dGd2tb6OSsuzixeV4y/faTqgFtohetphbbj0=" crossorigin="anonymous"></script>
  <script src="{{ url_for('static', filename='js/popper.min.js') }}"
          integrity="sha256-/ijcOLwFf26xEYAjW75FizKVo5tnTYiQddPZoLUHHZ8=" crossorigin="anonymous"></script>
  <script src="{{ url_for('static', filename='js/bootstrap.min.js') }}"
          integrity="sha256-ecWZ3XYM7AwWIaGvSdmipJ2l1F4bN9RXW6zgpeAiZYI=" crossorigin="anonymous"></script>
</body>
</html>
    """)
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    error_message = ""
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        if authenticate_user(username, password):
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            error_message = "Invalid username or password. Please try again."
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login - QRS</title>
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

    <!-- SRI kept EXACTLY the same -->
    <link rel="stylesheet" href="{{ url_for('static', filename='css/orbitron.css') }}" integrity="sha256-3mvPl5g2WhVLrUV4xX3KE8AV8FgrOz38KmWLqKXVh00=" crossorigin="anonymous">
    <link rel="stylesheet" href="{{ url_for('static', filename='css/bootstrap.min.css') }}"
          integrity="sha256-Ww++W3rXBfapN8SZitAvc9jw2Xb+Ixt0rvDsmWmQyTo=" crossorigin="anonymous">

    <style>
        body {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: #ffffff;
            font-family: 'Roboto', sans-serif;
        }
        /* Transparent navbar like Home */
        .navbar {
            background-color: transparent !important;
        }
        .navbar .nav-link { color: #fff; }
        .navbar .nav-link:hover { color: #66ff66; }

        .container { max-width: 400px; margin-top: 100px; }
        .Spotd { padding: 30px; background-color: rgba(255, 255, 255, 0.1); border: none; border-radius: 15px; }
        .error-message { color: #ff4d4d; }
        .brand { 
            font-family: 'Orbitron', sans-serif;
            font-size: 2.5rem; 
            font-weight: bold; 
            text-align: center; 
            margin-bottom: 20px; 
            background: -webkit-linear-gradient(#f0f, #0ff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        input, label, .btn, .error-message, a { color: #ffffff; }
        input::placeholder { color: #cccccc; opacity: 0.7; }
        .btn-primary { 
            background-color: #00cc00; 
            border-color: #00cc00; 
            font-weight: bold;
            transition: background-color 0.3s, border-color 0.3s;
        }
        .btn-primary:hover { 
            background-color: #33ff33; 
            border-color: #33ff33; 
        }
        a { text-decoration: none; }
        a:hover { text-decoration: underline; color: #66ff66; }
        @media (max-width: 768px) {
            .container { margin-top: 50px; }
            .brand { font-size: 2rem; }
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark">
        <a class="navbar-brand" href="{{ url_for('home') }}">QRS</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" 
            aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>

        <!-- Right side: ONLY Login / Register (no Dashboard, no dropdown) -->
        <div class="collapse navbar-collapse justify-content-end" id="navbarNav">
            <ul class="navbar-nav">
                <li class="nav-item"><a class="nav-link active" href="{{ url_for('login') }}">Login</a></li>
                <li class="nav-item"><a class="nav-link" href="{{ url_for('register') }}">Register</a></li>
            </ul>
        </div>
    </nav>

    <div class="container">
        <div class="Spotd shadow">
            <div class="brand">QRS</div>
            <h3 class="text-center">Login</h3>
            {% if error_message %}
            <p class="error-message text-center">{{ error_message }}</p>
            {% endif %}
            <form method="POST" novalidate>
                {{ form.hidden_tag() }}
                <div class="form-group">
                    {{ form.username.label }}
                    {{ form.username(class="form-control", placeholder="Enter your username") }}
                </div>
                <div class="form-group">
                    {{ form.password.label }}
                    {{ form.password(class="form-control", placeholder="Enter your password") }}
                </div>
                {{ form.submit(class="btn btn-primary btn-block") }}
            </form>
            <p class="mt-3 text-center">Don't have an account? <a href="{{ url_for('register') }}">Register here</a></p>
        </div>
    </div>

    <!-- Tiny vanilla JS to make the navbar collapse work without adding new JS files/SRIs -->
    <script>
    document.addEventListener('DOMContentLoaded', function () {
        var toggler = document.querySelector('.navbar-toggler');
        var nav = document.getElementById('navbarNav');
        if (toggler && nav) {
            toggler.addEventListener('click', function () {
                var isShown = nav.classList.toggle('show');
                toggler.setAttribute('aria-expanded', isShown ? 'true' : 'false');
            });
        }
    });
    </script>
</body>
</html>
    """,
        form=form,
        error_message=error_message)


@app.route('/register', methods=['GET', 'POST'])
def register():
    global registration_enabled
    error_message = ""
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        invite_code = form.invite_code.data if not registration_enabled else None

        success, message = register_user(username, password, invite_code)

        if success:
            flash(message, "success")
            return redirect(url_for('login'))
        else:
            error_message = message

    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Register - QRS</title>
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

    <!-- SRIs kept EXACTLY the same -->
    <link href="{{ url_for('static', filename='css/roboto.css') }}" rel="stylesheet"
          integrity="sha256-Sc7BtUKoWr6RBuNTT0MmuQjqGVQwYBK+21lB58JwUVE=" crossorigin="anonymous">
    <link href="{{ url_for('static', filename='css/orbitron.css') }}" rel="stylesheet"
          integrity="sha256-3mvPl5g2WhVLrUV4xX3KE8AV8FgrOz38KmWLqKXVh00=" crossorigin="anonymous">
    <link rel="stylesheet" href="{{ url_for('static', filename='css/bootstrap.min.css') }}"
          integrity="sha256-Ww++W3rXBfapN8SZitAvc9jw2Xb+Ixt0rvDsmWmQyTo=" crossorigin="anonymous">
    <link rel="stylesheet" href="{{ url_for('static', filename='css/fontawesome.min.css') }}"
          integrity="sha256-rx5u3IdaOCszi7Jb18XD9HSn8bNiEgAqWJbdBvIYYyU=" crossorigin="anonymous">

    <style>
        body {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: #ffffff;
            font-family: 'Roboto', sans-serif;
        }
        /* Transparent navbar like Home */
        .navbar { background-color: transparent !important; }
        .navbar .nav-link { color: #fff; }
        .navbar .nav-link:hover { color: #66ff66; }

        .container { max-width: 400px; margin-top: 100px; }
        .walkd { padding: 30px; background-color: rgba(255, 255, 255, 0.1); border: none; border-radius: 15px; }
        .error-message { color: #ff4d4d; }
        .brand {
            font-family: 'Orbitron', sans-serif;
            font-size: 2.5rem;
            font-weight: bold;
            text-align: center;
            margin-bottom: 20px;
            background: -webkit-linear-gradient(#f0f, #0ff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        input, label, .btn, .error-message, a { color: #ffffff; }
        input::placeholder { color: #cccccc; opacity: 0.7; }
        .btn-primary {
            background-color: #00cc00;
            border-color: #00cc00;
            font-weight: bold;
            transition: background-color 0.3s, border-color 0.3s;
        }
        .btn-primary:hover {
            background-color: #33ff33;
            border-color: #33ff33;
        }
        a { text-decoration: none; }
        a:hover { text-decoration: underline; color: #66ff66; }
        @media (max-width: 768px) {
            .container { margin-top: 50px; }
            .brand { font-size: 2rem; }
        }
    </style>
</head>
<body>
    <!-- Navbar: ONLY Login / Register (no Dashboard, no dropdown) -->
    <nav class="navbar navbar-expand-lg navbar-dark">
        <a class="navbar-brand" href="{{ url_for('home') }}">QRS</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav"
            aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>

        <div class="collapse navbar-collapse justify-content-end" id="navbarNav">
            <ul class="navbar-nav">
                <li class="nav-item"><a class="nav-link" href="{{ url_for('login') }}">Login</a></li>
                <li class="nav-item"><a class="nav-link active" href="{{ url_for('register') }}">Register</a></li>
            </ul>
        </div>
    </nav>

    <div class="container">
        <div class="walkd shadow">
            <div class="brand">CS</div>
            <h3 class="text-center">Register</h3>
            {% if error_message %}
            <p class="error-message text-center">{{ error_message }}</p>
            {% endif %}
            <form method="POST" novalidate>
                {{ form.hidden_tag() }}
                <div class="form-group">
                    {{ form.username.label }}
                    {{ form.username(class="form-control", placeholder="Choose a username") }}
                </div>
                <div class="form-group">
                    {{ form.password.label }}
                    {{ form.password(class="form-control", placeholder="Choose a password") }}
                    <small id="passwordStrength" class="form-text"></small>
                </div>
                {% if not registration_enabled %}
                <div class="form-group">
                    {{ form.invite_code.label }}
                    {{ form.invite_code(class="form-control", placeholder="Enter invite code") }}
                </div>
                {% endif %}
                {{ form.submit(class="btn btn-primary btn-block") }}
            </form>
            <p class="mt-3 text-center">Already have an account? <a href="{{ url_for('login') }}">Login here</a></p>
        </div>
    </div>

    <!-- Tiny vanilla JS to make the navbar collapse work without extra JS files -->
    <script>
    document.addEventListener('DOMContentLoaded', function () {
        var toggler = document.querySelector('.navbar-toggler');
        var nav = document.getElementById('navbarNav');
        if (toggler && nav) {
            toggler.addEventListener('click', function () {
                var isShown = nav.classList.toggle('show');
                toggler.setAttribute('aria-expanded', isShown ? 'true' : 'false');
            });
        }
    });
    </script>
</body>
</html>
    """,
        form=form,
        error_message=error_message,
        registration_enabled=registration_enabled)


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'is_admin' not in session or not session.get('is_admin'):
        return redirect(url_for('dashboard'))

    global registration_enabled
    message = ""
    new_invite_code = None
    form = SettingsForm()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'enable_registration':
            registration_enabled = True
            set_registration_enabled(True, get_user_id(session['username']))
            message = "Registration has been enabled."
        elif action == 'disable_registration':
            registration_enabled = False
            set_registration_enabled(False, get_user_id(session['username']))
            message = "Registration has been disabled."
        elif action == 'generate_invite_code':
            new_invite_code = generate_secure_invite_code()
            with sqlite3.connect(DB_FILE) as db:
                cursor = db.cursor()
                cursor.execute("INSERT INTO invite_codes (code) VALUES (?)",
                               (new_invite_code, ))
                db.commit()
            message = f"New invite code generated: {new_invite_code}"

    invite_codes = []
    with sqlite3.connect(DB_FILE) as db:
        cursor = db.cursor()
        cursor.execute("SELECT code FROM invite_codes WHERE is_used = 0")
        invite_codes = [row[0] for row in cursor.fetchall()]

    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Settings - QRS</title>
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link href="{{ url_for('static', filename='css/bootstrap.min.css') }}" rel="stylesheet"
          integrity="sha256-Ww++W3rXBfapN8SZitAvc9jw2Xb+Ixt0rvDsmWmQyTo=" crossorigin="anonymous">
    <link href="{{ url_for('static', filename='css/roboto.css') }}" rel="stylesheet"
          integrity="sha256-Sc7BtUKoWr6RBuNTT0MmuQjqGVQwYBK+21lB58JwUVE=" crossorigin="anonymous">
    <link href="{{ url_for('static', filename='css/orbitron.css') }}" rel="stylesheet"
          integrity="sha256-3mvPl5g2WhVLrUV4xX3KE8AV8FgrOz38KmWLqKXVh00" crossorigin="anonymous">
    <link rel="stylesheet" href="{{ url_for('static', filename='css/fontawesome.min.css') }}"
          integrity="sha256-rx5u3IdaOCszi7Jb18XD9HSn8bNiEgAqWJbdBvIYYyU=" crossorigin="anonymous">
    <style>
        body {
            background-color: #121212;
            color: #ffffff;
            font-family: 'Roboto', sans-serif;
        }
        .sidebar {
            position: fixed; 
            top: 0; 
            left: 0; 
            height: 100%; 
            width: 220px;
            background-color: #1f1f1f;
            padding-top: 60px;
            border-right: 1px solid #333;
            transition: width 0.3s;
        }
        .sidebar a {
            color: #bbbbbb; 
            padding: 15px 20px; 
            text-decoration: none; 
            display: block; 
            font-size: 1rem;
            transition: background-color 0.3s, color 0.3s;
        }
        .sidebar a:hover, .sidebar a.active {
            background-color: #333;
            color: #ffffff;
        }
        .content {
            margin-left: 220px; 
            padding: 20px;
            transition: margin-left 0.3s;
        }
        .navbar-brand {
            font-size: 1.5rem; 
            color: #ffffff; 
            text-align: center; 
            display: block; 
            margin-bottom: 20px;
            font-family: 'Orbitron', sans-serif;
        }
        .card {
            padding: 30px; 
            background-color: rgba(255, 255, 255, 0.1); 
            border: none; 
            border-radius: 15px; 
        }
        .message { color: #4dff4d; }
        .btn { 
            color: #ffffff; 
            font-weight: bold;
            transition: background-color 0.3s, border-color 0.3s;
        }
        .btn-success { 
            background-color: #00cc00; 
            border-color: #00cc00; 
        }
        .btn-success:hover { 
            background-color: #33ff33; 
            border-color: #33ff33; 
        }
        .btn-danger { 
            background-color: #cc0000; 
            border-color: #cc0000; 
        }
        .btn-danger:hover { 
            background-color: #ff3333; 
            border-color: #ff3333; 
        }
        .btn-primary { 
            background-color: #007bff; 
            border-color: #007bff; 
        }
        .btn-primary:hover { 
            background-color: #0056b3; 
            border-color: #0056b3; 
        }
        .invite-codes {
            margin-top: 20px;
        }
        .invite-code {
            background-color: #2c2c2c;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 5px;
            font-family: 'Courier New', Courier, monospace;
        }
        @media (max-width: 768px) {
            .sidebar { width: 60px; }
            .sidebar a { padding: 15px 10px; text-align: center; }
            .sidebar a span { display: none; }
            .content { margin-left: 60px; }
        }
    </style>
</head>
<body>

    <div class="sidebar">
        <div class="navbar-brand">QRS</div>
        <a href="{{ url_for('dashboard') }}" class="nav-link {% if active_page == 'dashboard' %}active{% endif %}">
            <i class="fas fa-home"></i> <span>Dashboard</span>
        </a>
        {% if session.get('is_admin') %}
        <a href="{{ url_for('settings') }}" class="nav-link {% if active_page == 'settings' %}active{% endif %}">
            <i class="fas fa-cogs"></i> <span>Settings</span>
        </a>
        {% endif %}
        <a href="{{ url_for('logout') }}" class="nav-link">
            <i class="fas fa-sign-out-alt"></i> <span>Logout</span>
        </a>
    </div>

    <div class="content">
        <h2>Settings</h2>

        {% if message %}
            <p class="message">{{ message }}</p>
        {% endif %}
        <form method="POST">
            {{ form.hidden_tag() }}
            <button type="submit" name="action" value="enable_registration" class="btn btn-success">Enable Registration</button>
            <button type="submit" name="action" value="disable_registration" class="btn btn-danger">Disable Registration</button>
        </form>
        <hr>
        <form method="POST">
            {{ form.hidden_tag() }}
            <button type="submit" name="action" value="generate_invite_code" class="btn btn-primary">Generate New Invite Code</button>
        </form>
        {% if new_invite_code %}
            <p>New Invite Code: {{ new_invite_code }}</p>
        {% endif %}
        <hr>
        <h4>Unused Invite Codes:</h4>
        <ul>
        {% for code in invite_codes %}
            <li>{{ code }}</li>
        {% else %}
            <p>No unused invite codes available.</p>
        {% endfor %}
        </ul>
    </div>
    <script src="{{ url_for('static', filename='js/jquery.min.js') }}"
            integrity="sha256-9/aliU8dGd2tb6OSsuzixeV4y/faTqgFtohetphbbj0=" crossorigin="anonymous"></script>
    <script src="{{ url_for('static', filename='js/popper.min.js') }}" integrity="sha256-/ijcOLwFf26xEYAjW75FizKVo5tnTYiQddPZoLUHHZ8=" crossorigin="anonymous"></script>
    <script src="{{ url_for('static', filename='js/bootstrap.min.js') }}"
            integrity="sha256-ecWZ3XYM7AwWIaGvSdmipJ2l1F4bN9RXW6zgpeAiZYI=" crossorigin="anonymous"></script>

</body>
</html>
    """,
                                  message=message,
                                  new_invite_code=new_invite_code,
                                  invite_codes=invite_codes,
                                  form=form)


@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('is_admin', None)
    return redirect(url_for('home'))


@app.route('/view_report/<int:report_id>', methods=['GET'])
def view_report(report_id):
    if 'username' not in session:
        logger.warning(
            f"Unauthorized access attempt to view_report by user: {session.get('username')}"
        )
        return redirect(url_for('login'))

    user_id = get_user_id(session['username'])
    report = get_hazard_report_by_id(report_id, user_id)
    if not report:
        logger.error(
            f"Report not found or access denied for report_id: {report_id} by user_id: {user_id}"
        )
        return "Report not found or access denied.", 404

    trigger_words = {
        'severity': {
            'low': -7,
            'medium': -0.2,
            'high': 14
        },
        'urgency': {
            'level': {
                'high': 14
            }
        },
        'low': -7,
        'medium': -0.2,
        'metal': 11,
    }

    text = (report['result'] or "").lower()
    words = re.findall(r'\w+', text)

    total_weight = 0
    for w in words:
        if w in trigger_words.get('severity', {}):
            total_weight += trigger_words['severity'][w]
        elif w == 'metal':
            total_weight += trigger_words['metal']

    if 'urgency level' in text and 'high' in text:
        total_weight += trigger_words['urgency']['level']['high']

    max_factor = 30.0
    if total_weight <= 0:
        ratio = 0.0
    else:
        ratio = min(total_weight / max_factor, 1.0)

    def interpolate_color(color1, color2, t):
        c1 = int(color1[1:], 16)
        c2 = int(color2[1:], 16)
        r1, g1, b1 = (c1 >> 16) & 0xff, (c1 >> 8) & 0xff, c1 & 0xff
        r2, g2, b2 = (c2 >> 16) & 0xff, (c2 >> 8) & 0xff, c2 & 0xff
        r = int(r1 + (r2 - r1) * t)
        g = int(g1 + (g2 - g1) * t)
        b = int(b1 + (b2 - b1) * t)
        return f"#{r:02x}{g:02x}{b:02x}"

    green = "#56ab2f"
    yellow = "#f4c95d"
    red = "#ff9068"

    if ratio < 0.5:
        t = ratio / 0.5
        wheel_color = interpolate_color(green, yellow, t)
    else:
        t = (ratio - 0.5) / 0.5
        wheel_color = interpolate_color(yellow, red, t)

    report_md = markdown(report['result'])
    allowed_tags = list(bleach.sanitizer.ALLOWED_TAGS) + [
        'p', 'ul', 'ol', 'li', 'strong', 'em', 'h1', 'h2', 'h3', 'h4', 'h5',
        'h6', 'br'
    ]
    report_html = bleach.clean(report_md, tags=allowed_tags)
    report_html_escaped = report_html.replace('\\', '\\\\')
    csrf_token = generate_csrf()

    return render_template_string(r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Report Details</title>
    <style>
        #view-report-container .btn-custom {
            width: 100%;
            padding: 15px;
            font-size: 1.2rem;
            background-color: #007bff;
            border: none;
            color: #ffffff;
            border-radius: 5px;
            transition: background-color 0.3s;
        }
        #view-report-container .btn-custom:hover {
            background-color: #0056b3;
        }
        #view-report-container .btn-danger {
            width: 100%;
            padding: 10px;
            font-size: 1rem;
        }

        .hazard-wheel {
            display: inline-block;
            width: 320px; 
            height: 320px; 
            border-radius: 50%;
            margin-right: 8px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            border: 2px solid #ffffff;
            background: {{ wheel_color }};
            background-size: cover;
            vertical-align: middle;
            display: flex;
            justify-content: center;
            align-items: center;
            color: #ffffff;
            font-weight: bold;
            font-size: 1.2rem;
            text-transform: capitalize;
            margin: auto;
            animation: breathing 3s infinite ease-in-out; /* Breathing animation */
        }

        @keyframes breathing {
            0% { transform: scale(1); }
            50% { transform: scale(1.1); }
            100% { transform: scale(1); }
        }

        .hazard-summary {
            text-align: center;
            margin-top: 20px;
        }

        .progress {
            background-color: #e9ecef;
        }

        .progress-bar {
            background-color: #007bff;
            color: #fff;
        }

        @media (max-width: 576px) {
            .hazard-wheel {
                width: 120px;
                height: 120px;
                font-size: 1rem;
            }
            #view-report-container .btn-custom {
                font-size: 1rem;
                padding: 10px;
            }
            .progress {
                height: 20px;
            }
            .progress-bar {
                font-size: 0.8rem;
                line-height: 20px;
            }
        }
    </style>
</head>
<body>
<div id="view-report-container">
    <div class="container mt-5">
        <div class="report-container">
            <div class="hazard-summary">
                <div class="hazard-wheel">Risk</div>
            </div>
            <button class="btn-custom mt-3" onclick="readAloud()" aria-label="Read Report">
                <i class="fas fa-volume-up" aria-hidden="true"></i> Read Report
            </button>
            <div class="mt-2">
                <button class="btn btn-danger btn-sm" onclick="stopSpeech()" aria-label="Stop Reading">
                    <i class="fas fa-stop" aria-hidden="true"></i> Stop
                </button>
            </div>
            <div class="progress mt-3" style="height: 25px;">
                <div id="speechProgressBar" class="progress-bar" role="progressbar" style="width: 0%;" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100">
                    0%
                </div>
            </div>
            <div id="reportMarkdown">{{ report_html_escaped | safe }}</div>
            <h4>Route Details</h4>
            <p><span class="report-text-bold">Date:</span> {{ report['timestamp'] }}</p>
            <p><span class="report-text-bold">Location:</span> {{ report['latitude'] }}, {{ report['longitude'] }}</p>
            <p><span class="report-text-bold">Nearest City:</span> {{ report['street_name'] }}</p>
            <p><span class="report-text-bold">Vehicle Type:</span> {{ report['vehicle_type'] }}</p>
            <p><span class="report-text-bold">Destination:</span> {{ report['destination'] }}</p>
            <p><span class="report-text-bold">Model Used:</span> {{ report['model_used'] }}</p>
            <div aria-live="polite" aria-atomic="true" id="speechStatus" class="sr-only">
                Speech synthesis is not active.
            </div>
        </div>
    </div>
</div>
<script>
    let synth = window.speechSynthesis;
    let utterances = [];
    let currentUtteranceIndex = 0;
    let isSpeaking = false;
    let availableVoices = [];
    let selectedVoice = null;
    let voicesLoaded = false;
    let originalReportHTML = null;

    const fillers = {
        start: ['umm, ', 'well, ', 'so, ', 'let me see, ', 'okay, ', 'hmm, ', 'right, ', 'alright, ', 'you know, ', 'basically, '],
        middle: ['you see, ', 'I mean, ', 'like, ', 'actually, ', 'for example, '],
        end: ['thats all.', 'so there you have it.', 'just so you know.', 'anyway.']
    };

    window.addEventListener('load', () => {
        originalReportHTML = document.getElementById('reportMarkdown').innerHTML;
        preloadVoices().catch((error) => {
            console.error("Failed to preload voices:", error);
        });
    });

    async function preloadVoices() {
        return new Promise((resolve, reject) => {
            function loadVoices() {
                availableVoices = synth.getVoices();
                if (availableVoices.length !== 0) {
                    voicesLoaded = true;
                    resolve();
                }
            }
            loadVoices();
            synth.onvoiceschanged = () => {
                loadVoices();
            };
            setTimeout(() => {
                if (availableVoices.length === 0) {
                    reject(new Error("Voices did not load in time."));
                }
            }, 5000);
        });
    }

    function selectBestVoice() {
        let voice = availableVoices.find(v => v.lang.startsWith('en') && v.name.toLowerCase().includes('female'));
        if (!voice) {
            voice = availableVoices.find(v => v.lang.startsWith('en'));
        }
        if (!voice && availableVoices.length > 0) {
            voice = availableVoices[0];
        }
        return voice;
    }

    function preprocessText(text) {
        const sentences = splitIntoSentences(text);
        const mergedSentences = mergeShortSentences(sentences);
        const preprocessedSentences = mergedSentences.map(sentence => {
            let fillerType = null;
            const rand = Math.random();
            if (rand < 0.02) {
                fillerType = 'start';
            } else if (rand >= 0.02 && rand < 0.04) {
                fillerType = 'middle';
            } else if (rand >= 0.04 && rand < 0.06) {
                fillerType = 'end';
            }
            if (fillerType) {
                let filler = fillers[fillerType][Math.floor(Math.random() * fillers[fillerType].length)];
                if (fillerType === 'middle') {
                    const words = sentence.split(' ');
                    const mid = Math.floor(words.length / 2);
                    words.splice(mid, 0, filler);
                    return words.join(' ');
                } else if (fillerType === 'end') {
                    return sentence.replace(/[.!?]+$/, '') + ' ' + filler;
                } else {
                    return filler + sentence;
                }
            }
            return sentence;
        });
        return preprocessedSentences.join(' ');
    }

    function splitIntoSentences(text) {
        text = text.replace(/\\d+/g, '');
        const sentenceEndings = /(?<!\\b(?:[A-Za-z]\\.|\d+\\.\\d+))(?<=\\.|\\!|\\?)(?=\\s+)/;

        return text.split(sentenceEndings).filter(sentence => sentence.trim().length > 0);
    }

    function mergeShortSentences(sentences) {
        const mergedSentences = [];
        let tempSentence = '';
        sentences.forEach(sentence => {
            if (sentence.length < 60 && tempSentence) {
                tempSentence += ' ' + sentence.trim();
            } else if (sentence.length < 60) {
                tempSentence = sentence.trim();
            } else {
                if (tempSentence) {
                    mergedSentences.push(tempSentence);
                    tempSentence = '';
                }
                mergedSentences.push(sentence.trim());
            }
        });
        if (tempSentence) {
            mergedSentences.push(tempSentence);
        }
        return mergedSentences;
    }

    function detectEmphasis(sentence) {
        const emphasisKeywords = ['cpu usage', 'ram usage', 'model used', 'destination', 'location'];
        return emphasisKeywords.filter(keyword => sentence.toLowerCase().includes(keyword));
    }

    function adjustSpeechParameters(utterance, sentence) {
        const emphasizedWords = detectEmphasis(sentence);
        if (emphasizedWords.length > 0) {
            utterance.pitch = 1.4;
            utterance.rate = 1.0;
        } else {
            utterance.pitch = 1.2;
            utterance.rate = 0.9;
        }
    }

    function initializeProgressBar(totalSentences) {
        const progressBar = document.getElementById('speechProgressBar');
        progressBar.style.width = '0%';
        progressBar.setAttribute('aria-valuenow', 0);
        progressBar.textContent = `0%`;
        progressBar.dataset.total = totalSentences;
        progressBar.dataset.current = 0;
    }

    function updateProgressBar() {
        const progressBar = document.getElementById('speechProgressBar');
        let current = parseInt(progressBar.dataset.current) + 1;
        const total = parseInt(progressBar.dataset.total);
        const percentage = Math.floor((current / total) * 100);
        progressBar.style.width = `${percentage}%`;
        progressBar.setAttribute('aria-valuenow', percentage);
        progressBar.textContent = `${percentage}%`;
        progressBar.dataset.current = current;
    }

    function updateSpeechStatus(status) {
        const speechStatus = document.getElementById('speechStatus');
        speechStatus.textContent = `Speech synthesis is ${status}.`;
    }

    async function readAloud() {
        if (!('speechSynthesis' in window)) {
            alert("Sorry, your browser does not support Speech Synthesis.");
            return;
        }
        if (isSpeaking) {
            alert("Speech is already in progress.");
            return;
        }
        if (!voicesLoaded) {
            try {
                await preloadVoices();
            } catch (error) {
                console.error("Error loading voices:", error);
                alert("Could not load voices for speech.");
                return;
            }
        }

        selectedVoice = selectBestVoice();
        if (!selectedVoice) {
            alert("No available voices for speech synthesis.");
            return;
        }

        const reportContentElement = document.getElementById('reportMarkdown');
        const reportContent = reportContentElement.innerText;
        const routeDetails = `
            Date: {{ report['timestamp'] }}.
            Location: {{ report['latitude'] }}, {{ report['longitude'] }}.
            Nearest City: {{ report['street_name'] }}.
            Vehicle Type: {{ report['vehicle_type'] }}.
            Destination: {{ report['destination'] }}.
            Model Used: {{ report['model_used'] }}.
        `;
        const combinedText = preprocessText(reportContent + ' ' + routeDetails);
        const sentences = splitIntoSentences(combinedText);

        initializeProgressBar(sentences.length);
        updateSpeechStatus('in progress');
        synth.cancel();
        utterances = [];
        currentUtteranceIndex = 0;
        isSpeaking = true;

        sentences.forEach((sentence) => {
            const utterance = new SpeechSynthesisUtterance(sentence.trim());
            adjustSpeechParameters(utterance, sentence);
            utterance.volume = 1;
            utterance.voice = selectedVoice;

            utterance.onend = () => {
                updateProgressBar();
                currentUtteranceIndex++;
                if (currentUtteranceIndex < utterances.length) {
                    synth.speak(utterances[currentUtteranceIndex]);
                } else {
                    isSpeaking = false;
                    updateSpeechStatus('not active');
                }
            };
            utterance.onerror = (event) => {
                console.error('SpeechSynthesisUtterance.onerror', event);
                alert("Speech has stopped");
                isSpeaking = false;
                updateSpeechStatus('not active');
            };
            utterances.push(utterance);
        });

        if (utterances.length > 0) {
            synth.speak(utterances[0]);
        }
    }

    function stopSpeech() {
        if (synth.speaking) {
            synth.cancel();
        }
        utterances = [];
        currentUtteranceIndex = 0;
        isSpeaking = false;
        updateSpeechStatus('not active');
    }

    document.addEventListener('keydown', function(event) {
        if (event.ctrlKey && event.altKey && event.key.toLowerCase() === 'r') {
            readAloud();
        }
        if (event.ctrlKey && event.altKey && event.key.toLowerCase() === 's') {
            stopSpeech();
        }
    });

    window.addEventListener('touchstart', () => {
        if (!voicesLoaded) {
            preloadVoices().catch(e => console.error(e));
        }
    }, { once: true });
</script>
</body>
</html>
    """,
                                  report=report,
                                  report_html_escaped=report_html_escaped,
                                  csrf_token=csrf_token,
                                  wheel_color=wheel_color)


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    user_id = get_user_id(username)
    reports = get_hazard_reports(user_id)
    csrf_token = generate_csrf()
    preferred_model = get_user_preferred_model(user_id)

    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard - Quantum Road Scanner</title>
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

    <link href="{{ url_for('static', filename='css/roboto.css') }}" rel="stylesheet"
          integrity="sha256-Sc7BtUKoWr6RBuNTT0MmuQjqGVQwYBK+21lB58JwUVE=" crossorigin="anonymous">
    <link href="{{ url_for('static', filename='css/orbitron.css') }}" rel="stylesheet"
          integrity="sha256-3mvPl5g2WhVLrUV4xX3KE8AV8FgrOz38KmWLqKXVh00" crossorigin="anonymous">
    <link rel="stylesheet" href="{{ url_for('static', filename='css/bootstrap.min.css') }}"
          integrity="sha256-Ww++W3rXBfapN8SZitAvc9jw2Xb+Ixt0rvDsmWmQyTo=" crossorigin="anonymous">
    <link rel="stylesheet" href="{{ url_for('static', filename='css/fontawesome.min.css') }}"
          integrity="sha256-rx5u3IdaOCszi7Jb18XD9HSn8bNiEgAqWJbdBvIYYyU=" crossorigin="anonymous">

    <style>
        body {
            background-color: #121212;
            color: #ffffff;
            font-family: 'Roboto', sans-serif;
        }
        .sidebar {
            position: fixed;
            top: 0;
            left: 0;
            height: 100%;
            width: 220px;
            background-color: #1f1f1f;
            padding-top: 60px;
            border-right: 1px solid #333;
            transition: width 0.3s;
        }
        .sidebar a {
            color: #bbbbbb;
            padding: 15px 20px;
            text-decoration: none;
            display: block;
            font-size: 1rem;
            transition: background-color 0.3s, color 0.3s;
        }
        .sidebar a:hover, .sidebar a.active {
            background-color: #333;
            color: #ffffff;
        }
        .content {
            margin-left: 220px;
            padding: 20px;
            transition: margin-left 0.3s;
        }
        .navbar-brand {
            font-size: 1.5rem;
            color: #ffffff;
            text-align: center;
            display: block;
            margin-bottom: 20px;
            font-family: 'Orbitron', sans-serif;
        }
        .stepper {
            display: flex;
            justify-content: space-between;
            margin-bottom: 30px;
        }
        .step {
            text-align: center;
            flex: 1;
            position: relative;
        }
        .step::before {
            content: '';
            position: absolute;
            top: 15px;
            right: -50%;
            width: 100%;
            height: 2px;
            background-color: #444;
            z-index: -1;
        }
        .step:last-child::before {
            display: none;
        }
        .step .circle {
            width: 30px;
            height: 30px;
            border-radius: 50%;
            background-color: #444;
            margin: 0 auto 10px;
            line-height: 30px;
            color: #fff;
            font-weight: bold;
        }
        .step.active .circle, .step.completed .circle {
            background-color: #00adb5;
        }
        .form-section {
            display: none;
        }
        .form-section.active {
            display: block;
        }
        .table thead th {
            background-color: #1f1f1f;
            color: #00adb5;
        }
        .table tbody td {
            color: #ffffff;
            background-color: #2c2c2c;
        }
        .modal-header {
            background-color: #1f1f1f;
            color: #00adb5;
        }
        .modal-body {
            background-color: #121212;
            color: #ffffff;
        }
        .btn-custom {
            background: #00adb5;
            border: none;
            color: #ffffff;
            padding: 10px 20px;
            border-radius: 5px;
            transition: background 0.3s;
        }
        .btn-custom:hover {
            background: #019a9e;
        }
        @media (max-width: 767px) {
            .sidebar { width: 60px; }
            .sidebar a { padding: 15px 10px; text-align: center; }
            .sidebar a span { display: none; }
            .content { margin-left: 60px; }
            .stepper {
                flex-direction: column;
            }
            .step::before {
                display: none;
            }
        }
    </style>
</head>
<body>

    <div class="sidebar">
        <div class="navbar-brand">QRS</div>
        <a href="#" class="nav-link active" onclick="showSection('step1')">
            <i class="fas fa-home"></i> <span>Dashboard</span>
        </a>
        {% if session.is_admin %}
        <a href="{{ url_for('settings') }}">
            <i class="fas fa-cogs"></i> <span>Settings</span>
        </a>
        {% endif %}
        <a href="{{ url_for('logout') }}">
            <i class="fas fa-sign-out-alt"></i> <span>Logout</span>
        </a>
    </div>

    <div class="content">
        <div class="stepper">
            <div class="step active" id="stepper1">
                <div class="circle">1</div>
                Grabs
            </div>
            <div class="step" id="stepper2">
                <div class="circle">2</div>
                Street Name
            </div>
            <div class="step" id="stepper3">
                <div class="circle">3</div>
                Run Scan
            </div>
        </div>

        <div id="step1" class="form-section active">
            <form id="grabCoordinatesForm">
                <div class="form-group">
                    <label for="latitude">Latitude</label>
                    <input type="text" class="form-control" id="latitude" name="latitude" placeholder="Enter latitude" required>
                </div>
                <div class="form-group">
                    <label for="longitude">Longitude</label>
                    <input type="text" class="form-control" id="longitude" name="longitude" placeholder="Enter longitude" required>
                </div>
                <button type="button" class="btn btn-custom" onclick="getCoordinates()">
                    <i class="fas fa-location-arrow"></i> Get Current Location
                </button>
                <button type="button" class="btn btn-custom" onclick="nextStep(1)">
                    <i class="fas fa-arrow-right"></i> Next
                </button>
            </form>
            <div id="statusMessage1" class="mt-3"></div>
        </div>

        <div id="step2" class="form-section">
            <h4>Street Name</h4>
            <p id="streetName">Fetching street name...</p>
            <button type="button" class="btn btn-custom" onclick="nextStep(2)">
                <i class="fas fa-arrow-right"></i> Next
            </button>
        </div>

        <div id="step3" class="form-section">
            <form id="runScanForm">
                <div class="form-group">
                    <label for="vehicle_type">Vehicle Type</label>
                    <select class="form-control" id="vehicle_type" name="vehicle_type">
                        <option value="motorbike">Motorbike</option>
                        <option value="car">Car</option>
                        <option value="truck">Truck</option>

                    </select>
                </div>
                <div class="form-group">
                    <label for="destination">Destination</label>
                    <input type="text" class="form-control" id="destination" name="destination" placeholder="Enter destination" required>
                </div>
                <div class="form-group">
                    <label for="model_selection">Select Model</label>
                    <select class="form-control" id="model_selection" name="model_selection">

                        <option value="openai" {% if preferred_model == 'openai' %}selected{% endif %}>OpenAI</option>

                    </select>
                </div>
                <button type="button" class="btn btn-custom" onclick="startScan()">
                    <i class="fas fa-play"></i> Start Scan
                </button>
            </form>
            <div id="statusMessage3" class="mt-3"></div>
        </div>

        <div id="reportsSection" class="mt-5">
            <h3>Your Reports</h3>
            {% if reports %}
            <table class="table table-dark table-hover">
                <thead>
                    <tr>
                        <th>Date</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for report in reports %}
                    <tr>
                        <td>{{ report['timestamp'] }}</td>
                        <td>
                            <button class="btn btn-info btn-sm" onclick="viewReport({{ report['id'] }})">
                                <i class="fas fa-eye"></i> View
                            </button>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <p>No reports available.</p>
            {% endif %}
        </div>
    </div>

    <div class="modal fade" id="reportModal" tabindex="-1" aria-labelledby="reportModalLabel" aria-hidden="true">
      <div class="modal-dialog modal-lg">
        <div class="modal-content">
          <div class="modal-header">
            <button type="button" class="close" data-dismiss="modal" aria-label="Close">
              <span aria-hidden="true">&times;</span>
            </button>
          </div>
          <div class="modal-body" id="reportContent">
          </div>
        </div>
      </div>
    </div>

    <div class="loading-spinner" style="display: none; position: fixed; top: 50%; left: 50%; z-index: 9999; width: 3rem; height: 3rem;">
        <div class="spinner-border text-primary" role="status">
            <span class="sr-only">Scanning...</span>
        </div>
    </div>

    <script src="{{ url_for('static', filename='js/jquery.min.js') }}"
            integrity="sha256-9/aliU8dGd2tb6OSsuzixeV4y/faTqgFtohetphbbj0=" crossorigin="anonymous"></script>
    <script src="{{ url_for('static', filename='js/popper.min.js') }}"
            integrity="sha256-/ijcOLwFf26xEYAjW75FizKVo5tnTYiQddPZoLUHHZ8=" crossorigin="anonymous"></script>
    <script src="{{ url_for('static', filename='js/bootstrap.min.js') }}"
            integrity="sha256-ecWZ3XYM7AwWIaGvSdmipJ2l1F4bN9RXW6zgpeAiZYI=" crossorigin="anonymous"></script>

    <script>
        var csrf_token = {{ csrf_token | tojson }};

        $.ajaxSetup({
            beforeSend: function(xhr, settings) {
                if (!/^GET|HEAD|OPTIONS|TRACE$/i.test(settings.type) && !this.crossDomain) {
                    xhr.setRequestHeader("X-CSRFToken", csrf_token);
                }
            }
        });

        var currentStep = 1;

        function showSection(step) {
            $('.form-section').removeClass('active');
            $('#' + step).addClass('active');
            updateStepper(step);
        }

        function updateStepper(step) {
            $('.step').removeClass('active completed');
            for(var i=1; i<=step; i++) {
                $('#stepper' + i).addClass('completed');
            }
            $('#stepper' + step).addClass('active');
        }

        function getCoordinates() {
            if (navigator.geolocation) {
                navigator.geolocation.getCurrentPosition(function(position) {
                    $('#latitude').val(position.coords.latitude);
                    $('#longitude').val(position.coords.longitude);
                }, function(error) {
                    alert("Error obtaining location: " + error.message);
                });
            } else {
                alert("Geolocation is not supported by this browser.");
            }
        }

        async function fetchStreetName(lat, lon) {
            try {
                const response = await fetch(`/reverse_geocode?lat=${lat}&lon=${lon}`);
                if (!response.ok) {
                    const errorData = await response.json();
                    throw new Error(errorData.error || 'Geocoding failed');
                }
                const data = await response.json();
                return data.street_name || "Unknown Location";
            } catch (error) {
                console.error(error);
                return "Geocoding Error";
            }
        }

        async function nextStep(step) {
            if(step === 1) {
                const lat = $('#latitude').val();
                const lon = $('#longitude').val();
                if(!lat || !lon) {
                    alert("Please enter both latitude and longitude.");
                    return;
                }
                $('#streetName').text("Fetching street name...");
                const streetName = await fetchStreetName(lat, lon);
                $('#streetName').text(streetName);
                showSection('step2');
            } else if(step === 2) {
                showSection('step3');
            }
        }

        async function startScan() {
            const lat = $('#latitude').val();
            const lon = $('#longitude').val();
            const vehicle_type = $('#vehicle_type').val();
            const destination = $('#destination').val();
            const model_selection = $('#model_selection').val();

            if(!vehicle_type || !destination) {
                alert("Please select vehicle type and enter destination.");
                return;
            }

            $('#statusMessage3').text("Scan started. Please wait...");
            $('.loading-spinner').show();

            const formData = {
                latitude: lat,
                longitude: lon,
                vehicle_type: vehicle_type,
                destination: destination,
                model_selection: model_selection
            };

            try {
                const response = await fetch('/start_scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': csrf_token
                    },
                    body: JSON.stringify(formData)
                });

                if (!response.ok) {
                    const errorData = await response.json();
                    $('.loading-spinner').hide();
                    $('#statusMessage3').text("Error: " + (errorData.error || 'Unknown error occurred.'));
                    return;
                }

                const data = await response.json();
                $('.loading-spinner').hide();
                $('#statusMessage3').text(data.message);

                if (data.report_id) {

                    viewReport(data.report_id);

                }
            } catch (error) {
                $('.loading-spinner').hide();
                $('#statusMessage3').text("An error occurred during the scan.");
                console.error('Error:', error);
            }
        }

        function viewReport(reportId) {
            $.ajax({
                url: '/view_report/' + reportId,
                method: 'GET',
                success: function(data) {
                    $('#reportContent').html(data); 
                    $('#reportModal').modal('show');
                },
                error: function(xhr, status, error) {
                    alert("An error occurred while fetching the report.");
                    console.error('Error:', error);
                }
            });
        }

        function prependReportToTable(reportId, timestamp) {
            const newRow = `
                <tr>
                    <td>${timestamp}</td>
                    <td>
                        <button class="btn btn-info btn-sm" onclick="viewReport(${reportId})">
                            <i class="fas fa-eye"></i> View
                        </button>
                    </td>
                </tr>
            `;
            $('table tbody').prepend(newRow);
        }

        $(document).ready(function() {
            showSection('step1');
        });
    </script>
</body>
</html>
    """,
                                  reports=reports,
                                  csrf_token=csrf_token,
                                  preferred_model=preferred_model)


def calculate_harm_level(result):
    if re.search(r'\b(high|severe|critical|urgent|dangerous)\b', result,
                 re.IGNORECASE):
        return "High"
    elif re.search(r'\b(medium|moderate|caution|warning)\b', result,
                   re.IGNORECASE):
        return "Medium"
    elif re.search(r'\b(low|minimal|safe|minor|normal)\b', result,
                   re.IGNORECASE):
        return "Low"
    return "Neutral"


@app.route('/start_scan', methods=['POST'])
async def start_scan_route():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user_id = get_user_id(username)

    if user_id is None:
        return jsonify({"error": "User not found"}), 404

    if not session.get('is_admin', False):
        if not check_rate_limit(user_id):
            return jsonify({"error":
                            "Rate limit exceeded. Try again later."}), 429

    data = request.get_json()

    lat = sanitize_input(data.get('latitude'))
    lon = sanitize_input(data.get('longitude'))
    vehicle_type = sanitize_input(data.get('vehicle_type'))
    destination = sanitize_input(data.get('destination'))
    model_selection = sanitize_input(data.get('model_selection'))

    if not lat or not lon or not vehicle_type or not destination or not model_selection:
        return jsonify({"error": "Missing required data"}), 400

    try:
        lat_float = parse_safe_float(lat)
        lon_float = parse_safe_float(lon)
    except ValueError:
        return jsonify({"error": "Invalid latitude or longitude format."}), 400

    combined_input = f"Vehicle Type: {vehicle_type}\nDestination: {destination}"
    is_allowed, analysis = await phf_filter_input(combined_input)
    if not is_allowed:
        return jsonify({
            "error": "Input contains disallowed content.",
            "details": analysis
        }), 400

    result, cpu_usage, ram_usage, quantum_results, street_name, model_used = await scan_debris_for_route(
        lat_float,
        lon_float,
        vehicle_type,
        destination,
        user_id,
        selected_model=model_selection
    )

    harm_level = calculate_harm_level(result)

    report_id = save_hazard_report(
        lat_float, lon_float, street_name,
        vehicle_type, destination, result,
        cpu_usage, ram_usage, quantum_results,
        user_id, harm_level, model_used
    )

    return jsonify({
        "message": "Scan completed successfully",
        "result": result,
        "harm_level": harm_level,
        "model_used": model_used,
        "report_id": report_id
    })


@app.route('/reverse_geocode', methods=['GET'])
async def reverse_geocode_route():
    if 'username' not in session:
        logger.warning("Unauthorized access attempt to /reverse_geocode.")
        return jsonify({"error": "Authentication required."}), 401

    lat = request.args.get('lat')
    lon = request.args.get('lon')

    if not lat or not lon:
        logger.error("Missing latitude or longitude parameters.")
        return jsonify({"error": "Missing parameters."}), 400

    try:
        lat = parse_safe_float(lat)
        lon = parse_safe_float(lon)
    except ValueError:
        logger.error("Invalid latitude or longitude format.")
        return jsonify({"error": "Invalid coordinate format."}), 400

    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        logger.error("Coordinates out of valid range.")
        return jsonify({"error": "Coordinates out of range."}), 400

    try:
        street_name = await fetch_street_name_llm(lat, lon)
        logger.info(f"Successfully resolved street name using LLM: {street_name}")
        return jsonify({"street_name": street_name}), 200
    except Exception as e:
        logger.warning(
            "LLM geocoding failed, falling back to standard reverse_geocode.",
            exc_info=True
        )

        try:
            street_name = reverse_geocode(lat, lon, cities)
            logger.info(f"Successfully resolved street name using fallback method: {street_name}")
            return jsonify({"street_name": street_name}), 200
        except Exception as fallback_e:
            logger.exception(
                f"Both LLM and fallback reverse geocoding failed: {fallback_e}"
            )
            return jsonify({"error": "Internal server error."}), 500


if __name__ == '__main__':
    serve(app, host='0.0.0.0', port=3000, threads=4)
