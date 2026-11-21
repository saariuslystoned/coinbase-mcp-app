"""Pure-stdlib ECDSA P-256 (ES256) CDP JWT signing and strict key-file prechecks.

No third-party runtime dependencies: parses SEC1 (RFC 5915) and PKCS#8 (RFC 5208)
PEM private keys on NIST P-256 (secp256r1), signs ES256 JWTs with RFC 6979
deterministic nonces, and rejects Ed25519 or non-P256 keys before any network call.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import stat
import subprocess
import time
from pathlib import Path

from .errors import AppError

COINBASE_HOST = "api.coinbase.com"

# NIST P-256 (secp256r1 / prime256v1) domain parameters (FIPS 186-4 / SEC 2).
_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_A = _P - 3
_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

# DER-encoded OIDs (value bytes only, excluding tag 0x06 and length).
_OID_EC_PUBLIC_KEY = bytes.fromhex("2a8648ce3d0201")  # 1.2.840.10045.2.1
_OID_SECP256R1 = bytes.fromhex("2a8648ce3d030107")  # 1.2.840.10045.3.1.7
_OID_ED25519 = bytes.fromhex("2b6570")  # 1.3.101.112

_PEM_BOUNDARY = "-----"
_PEM_EC_BEGIN = f"{_PEM_BOUNDARY}BEGIN EC PRIVATE KEY{_PEM_BOUNDARY}"
_PEM_EC_END = f"{_PEM_BOUNDARY}END EC PRIVATE KEY{_PEM_BOUNDARY}"
_PEM_PKCS8_BEGIN = f"{_PEM_BOUNDARY}BEGIN PRIVATE KEY{_PEM_BOUNDARY}"
_MAX_KEY_FILE_BYTES = 64 * 1024


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _jac_double(pt: tuple[int, int, int]) -> tuple[int, int, int]:
    x1, y1, z1 = pt
    if z1 == 0 or y1 == 0:
        return (0, 1, 0)
    z1_sq = (z1 * z1) % _P
    # a = -3 optimization: m = 3 * (x1 - z1^2) * (x1 + z1^2)
    m = (3 * (x1 - z1_sq) * (x1 + z1_sq)) % _P
    y1_sq = (y1 * y1) % _P
    s = (4 * x1 * y1_sq) % _P
    x3 = (m * m - 2 * s) % _P
    y3 = (m * (s - x3) - 8 * y1_sq * y1_sq) % _P
    z3 = (2 * y1 * z1) % _P
    return (x3, y3, z3)


def _jac_add(p1: tuple[int, int, int], p2: tuple[int, int, int]) -> tuple[int, int, int]:
    x1, y1, z1 = p1
    x2, y2, z2 = p2
    if z1 == 0:
        return p2
    if z2 == 0:
        return p1
    z1_sq = (z1 * z1) % _P
    z2_sq = (z2 * z2) % _P
    u1 = (x1 * z2_sq) % _P
    u2 = (x2 * z1_sq) % _P
    s1 = (y1 * z2 * z2_sq) % _P
    s2 = (y2 * z1 * z1_sq) % _P
    if u1 == u2:
        if s1 != s2:
            return (0, 1, 0)
        return _jac_double(p1)
    h = (u2 - u1) % _P
    r = (s2 - s1) % _P
    h_sq = (h * h) % _P
    h_cu = (h * h_sq) % _P
    u1_h_sq = (u1 * h_sq) % _P
    x3 = (r * r - h_cu - 2 * u1_h_sq) % _P
    y3 = (r * (u1_h_sq - x3) - s1 * h_cu) % _P
    z3 = (h * z1 * z2) % _P
    return (x3, y3, z3)


def _point_mul(k: int, point: tuple[int, int] = (_GX, _GY)) -> tuple[int, int] | None:
    if k % _N == 0:
        return None
    acc = (0, 1, 0)
    addend = (point[0] % _P, point[1] % _P, 1)
    scalar = k % _N
    while scalar:
        if scalar & 1:
            acc = _jac_add(acc, addend)
        addend = _jac_double(addend)
        scalar >>= 1
    x, y, z = acc
    if z == 0:
        return None
    z_inv = pow(z, -1, _P)
    z_inv_sq = (z_inv * z_inv) % _P
    return ((x * z_inv_sq) % _P, (y * z_inv_sq * z_inv) % _P)


def public_point_from_secret(d: int) -> tuple[int, int]:
    if not 1 <= d < _N:
        raise ValueError("ECDSA P-256 private scalar out of range")
    pt = _point_mul(d)
    if pt is None:
        raise ValueError("Invalid ECDSA P-256 public point")
    return pt


def _rfc6979_k(private_scalar: int, msg_hash: bytes) -> int:
    """RFC 6979 section 3.2 deterministic k for P-256 + SHA-256."""
    h1_int = int.from_bytes(msg_hash, "big") % _N
    bx = private_scalar.to_bytes(32, "big") + h1_int.to_bytes(32, "big")
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + bx, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + bx, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < _N:
            return candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign_p256_raw(private_scalar: int, message: bytes) -> bytes:
    """Sign message with ES256 (SHA-256 + P-256), returning 64-byte raw r||s."""
    digest = hashlib.sha256(message).digest()
    z = int.from_bytes(digest, "big")
    k = _rfc6979_k(private_scalar, digest)
    while True:
        pt = _point_mul(k)
        if pt is not None:
            r = pt[0] % _N
            if r != 0:
                s = (pow(k, -1, _N) * (z + r * private_scalar)) % _N
                if s != 0:
                    return r.to_bytes(32, "big") + s.to_bytes(32, "big")
        k = (k + 1) % _N or 1


def verify_p256_raw(public_point: tuple[int, int], message: bytes, sig_raw: bytes) -> bool:
    """Verify a 64-byte raw r||s ES256 signature on NIST P-256."""
    if len(sig_raw) != 64:
        return False
    r = int.from_bytes(sig_raw[:32], "big")
    s = int.from_bytes(sig_raw[32:], "big")
    if not (1 <= r < _N and 1 <= s < _N):
        return False
    px, py = public_point
    if (py * py - (px * px * px + _A * px + _B)) % _P != 0:
        return False
    z = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = pow(s, -1, _N)
    u1 = (z * w) % _N
    u2 = (r * w) % _N
    p1 = _point_mul(u1, (_GX, _GY))
    p2 = _point_mul(u2, public_point)
    if p1 is None or p2 is None:
        return False
    x, y, zj = _jac_add((p1[0], p1[1], 1), (p2[0], p2[1], 1))
    if zj == 0:
        return False
    z_inv = pow(zj, -1, _P)
    rx = (x * z_inv * z_inv) % _P
    return rx % _N == r


def _der_read_tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    if offset >= len(data):
        raise ValueError("Truncated DER element")
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise ValueError("Truncated DER length")
    first = data[offset]
    offset += 1
    if first < 0x80:
        length = first
    else:
        num_bytes = first & 0x7F
        if num_bytes == 0 or offset + num_bytes > len(data):
            raise ValueError("Invalid DER length")
        length = int.from_bytes(data[offset : offset + num_bytes], "big")
        offset += num_bytes
    end = offset + length
    if end > len(data):
        raise ValueError("DER element overflows buffer")
    return tag, data[offset:end], end


def _der_children(seq_body: bytes) -> list[tuple[int, bytes]]:
    items = []
    pos = 0
    while pos < len(seq_body):
        tag, val, pos = _der_read_tlv(seq_body, pos)
        items.append((tag, val))
    return items


def _parse_sec1_p256(der: bytes, *, curve_verified: bool = False) -> int:
    tag, body, end = _der_read_tlv(der, 0)
    if tag != 0x30 or end != len(der):
        raise ValueError("Expected SEC1 SEQUENCE")
    children = _der_children(body)
    if len(children) < 2 or children[0] != (0x02, b"\x01") or children[1][0] != 0x04:
        raise ValueError("Invalid SEC1 ECPrivateKey structure")
    scalar_bytes = children[1][1]
    if not curve_verified:
        found_oid: bytes | None = None
        for ctag, cval in children[2:]:
            if ctag == 0xA0:
                otag, oval, oend = _der_read_tlv(cval, 0)
                if otag == 0x06 and oend == len(cval):
                    found_oid = oval
        if found_oid != _OID_SECP256R1:
            raise AppError(
                "UNSUPPORTED_KEY_ALGORITHM",
                "Coinbase Advanced Trade API requires an ECDSA P-256 (ES256) key.",
                "Create a view-only ECDSA (not Ed25519) CDP API key.",
                4,
            )
    d = int.from_bytes(scalar_bytes, "big")
    if not 1 <= d < _N:
        raise ValueError("SEC1 private scalar out of P-256 range")
    return d


def parse_ecdsa_p256_pem(pem_text: str) -> int:
    """Parse SEC1 or PKCS#8 PEM private key and return NIST P-256 scalar d."""
    lines = [line.strip() for line in pem_text.strip().splitlines() if line.strip()]
    if len(lines) < 3 or not lines[0].startswith(f"{_PEM_BOUNDARY}BEGIN ") or not lines[-1].startswith(f"{_PEM_BOUNDARY}END "):
        raise AppError(
            "INVALID_KEY_FILE",
            "The Coinbase key file does not contain a valid PEM private key.",
            "Provide a Coinbase CDP ECDSA JSON key file.",
            4,
        )
    header = lines[0]
    try:
        der = base64.b64decode("".join(lines[1:-1]), validate=True)
    except ValueError as exc:
        raise AppError(
            "INVALID_KEY_FILE",
            "The Coinbase key file PEM payload cannot be decoded.",
            "Provide an unmodified Coinbase CDP ECDSA JSON key file.",
            4,
        ) from exc

    if header == _PEM_EC_BEGIN:
        try:
            return _parse_sec1_p256(der, curve_verified=False)
        except AppError:
            raise
        except ValueError as exc:
            raise AppError(
                "INVALID_KEY_FILE",
                "Cannot parse SEC1 EC private key.",
                "Provide a valid Coinbase CDP ECDSA P-256 JSON key file.",
                4,
            ) from exc

    if header == _PEM_PKCS8_BEGIN:
        try:
            tag, body, end = _der_read_tlv(der, 0)
            if tag != 0x30 or end != len(der):
                raise ValueError("Expected PKCS#8 SEQUENCE")
            children = _der_children(body)
            if len(children) < 3 or children[0][0] != 0x02 or children[1][0] != 0x30 or children[2][0] != 0x04:
                raise ValueError("Invalid PKCS#8 PrivateKeyInfo")
            alg_items = _der_children(children[1][1])
            if not alg_items or alg_items[0][0] != 0x06:
                raise ValueError("Missing PKCS#8 algorithm OID")
            alg_oid = alg_items[0][1]
            if alg_oid == _OID_ED25519:
                raise AppError(
                    "UNSUPPORTED_KEY_ALGORITHM",
                    "Ed25519 keys are unsupported for Coinbase Advanced Trade API; ES256 (ECDSA P-256) is required.",
                    "Create a view-only ECDSA CDP API key.",
                    4,
                )
            if alg_oid != _OID_EC_PUBLIC_KEY or len(alg_items) < 2 or alg_items[1] != (0x06, _OID_SECP256R1):
                raise AppError(
                    "UNSUPPORTED_KEY_ALGORITHM",
                    "Coinbase Advanced Trade API requires an ECDSA P-256 (ES256) key.",
                    "Create a view-only ECDSA CDP API key.",
                    4,
                )
            return _parse_sec1_p256(children[2][1], curve_verified=True)
        except AppError:
            raise
        except ValueError as exc:
            raise AppError(
                "INVALID_KEY_FILE",
                "Cannot parse PKCS#8 EC private key.",
                "Provide a valid Coinbase CDP ECDSA P-256 JSON key file.",
                4,
            ) from exc

    raise AppError(
        "UNSUPPORTED_KEY_ALGORITHM",
        "Unsupported private key PEM header; expected ECDSA P-256 (SEC1 or PKCS#8).",
        "Create a view-only ECDSA CDP API key.",
        4,
    )


def _is_inside_git_repo(parent_dir: Path) -> bool:
    for candidate in (parent_dir, *parent_dir.parents):
        if (candidate / ".git").exists():
            return True
    try:
        proc = subprocess.run(
            ["git", "-C", str(parent_dir), "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip().lower() == "true":
            return True
    except (OSError, subprocess.SubprocessError):
        pass
    return False


def load_cdp_key_file(key_file: str | Path) -> tuple[str, int]:
    """Validate key-file metadata and load (key_name, p256_scalar) in-process only.

    Never echoes the path or key material in errors.
    """
    if not isinstance(key_file, (str, Path)) or not str(key_file).strip():
        raise AppError(
            "COINBASE_KEY_REQUIRED",
            "A local view-only Coinbase CDP API key file is required.",
            "Pass --key-file PATH or set COINBASE_KEY_FILE to a mode-0600 file outside Git.",
            4,
        )
    raw_path = Path(os.path.expanduser(str(key_file)))
    try:
        lst = os.lstat(raw_path)
    except FileNotFoundError:
        raise AppError(
            "KEY_FILE_UNAVAILABLE",
            "The configured Coinbase key file does not exist.",
            "Check --key-file or COINBASE_KEY_FILE and retry.",
            4,
        ) from None
    except OSError:
        raise AppError(
            "KEY_FILE_UNAVAILABLE",
            "The configured Coinbase key file cannot be accessed.",
            "Check file permissions and retry.",
            4,
        ) from None

    if stat.S_ISLNK(lst.st_mode) or not stat.S_ISREG(lst.st_mode):
        raise AppError(
            "KEY_FILE_INSECURE",
            "The Coinbase key file must be a regular file, not a symlink or special file.",
            "Store the CDP key as a regular mode-0600 file outside any Git repository.",
            4,
        )
    if os.name == "posix":
        if lst.st_uid != os.getuid() or stat.S_IMODE(lst.st_mode) != 0o600:
            raise AppError(
                "KEY_FILE_INSECURE",
                "The Coinbase key file must be owned by the current user with exact mode 0600.",
                "Run chmod 600 on the private key file outside Git and retry.",
                4,
            )

    abs_parent = raw_path.absolute().parent
    resolved_parent = raw_path.resolve().parent
    if _is_inside_git_repo(abs_parent) or (resolved_parent != abs_parent and _is_inside_git_repo(resolved_parent)):
        raise AppError(
            "KEY_FILE_IN_GIT_REPO",
            "Refused Coinbase key file located inside a Git repository.",
            "Move the key file outside any Git repository with mode 0600 and retry.",
            4,
        )

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(raw_path, flags)
    except OSError:
        raise AppError(
            "KEY_FILE_UNAVAILABLE",
            "Cannot open the Coinbase key file safely.",
            "Verify the key file is a regular owner-only file and retry.",
            4,
        ) from None

    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode) or (
            os.name == "posix" and (fst.st_uid != os.getuid() or stat.S_IMODE(fst.st_mode) != 0o600)
        ):
            raise AppError(
                "KEY_FILE_INSECURE",
                "Key file metadata changed during open; refused.",
                "Verify key file ownership and mode 0600.",
                4,
            )
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            raw_bytes = handle.read(_MAX_KEY_FILE_BYTES + 1)
    finally:
        if fd >= 0:
            os.close(fd)

    if len(raw_bytes) > _MAX_KEY_FILE_BYTES:
        raise AppError(
            "INVALID_KEY_FILE",
            "The Coinbase key file exceeds the 64 KiB size limit.",
            "Provide a standard Coinbase CDP API key JSON file.",
            4,
        )

    try:
        payload = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise AppError(
            "INVALID_KEY_FILE",
            "The Coinbase key file must be valid UTF-8 JSON.",
            "Provide a standard Coinbase CDP API key JSON file.",
            4,
        ) from None

    if not isinstance(payload, dict):
        raise AppError(
            "INVALID_KEY_FILE",
            "The Coinbase key file root must be a JSON object.",
            "Provide a standard Coinbase CDP API key JSON file.",
            4,
        )

    key_name = None
    for field in ("name", "id"):
        candidate = payload.get(field)
        if isinstance(candidate, str) and candidate.strip():
            key_name = candidate.strip()
            break
    if not key_name:
        raise AppError(
            "INVALID_KEY_FILE",
            "The Coinbase key file is missing a non-empty 'name' or 'id' field.",
            "Provide a standard Coinbase CDP API key JSON file.",
            4,
        )

    private_pem = None
    for field in ("privateKey", "private_key"):
        candidate = payload.get(field)
        if isinstance(candidate, str) and candidate.strip():
            private_pem = candidate.replace("\\n", "\n")
            break
    if not private_pem:
        raise AppError(
            "INVALID_KEY_FILE",
            "The Coinbase key file is missing a non-empty 'privateKey' field.",
            "Provide a standard Coinbase CDP API key JSON file.",
            4,
        )

    scalar = parse_ecdsa_p256_pem(private_pem)
    return key_name, scalar


def build_cdp_es256_jwt(
    *,
    key_name: str,
    private_scalar: int,
    method: str,
    request_path: str,
    now: int | None = None,
    nonce: str | None = None,
) -> str:
    """Build a 2-minute per-request ES256 JWT for api.coinbase.com."""
    if "?" in request_path or not request_path.startswith("/"):
        raise ValueError("JWT signing path must be an absolute path without query parameters")
    issued_at = int(time.time()) if now is None else int(now)
    header = {
        "alg": "ES256",
        "typ": "JWT",
        "kid": key_name,
        "nonce": nonce if nonce is not None else secrets.token_hex(16),
    }
    payload = {
        "sub": key_name,
        "iss": "cdp",
        "nbf": issued_at,
        "exp": issued_at + 120,
        "uri": f"{method.upper()} {COINBASE_HOST}{request_path}",
    }
    header_b64 = _b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    payload_b64 = _b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig_raw = sign_p256_raw(private_scalar, signing_input)
    return f"{header_b64}.{payload_b64}.{_b64url(sig_raw)}"


def verify_es256_jwt(token: str, public_point: tuple[int, int]) -> tuple[dict, dict]:
    """Verify an ES256 JWT purely in stdlib; returns (header, payload)."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT segment count")
    header_b64, payload_b64, sig_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig_raw = _b64url_decode(sig_b64)
    if not verify_p256_raw(public_point, signing_input, sig_raw):
        raise ValueError("Invalid ES256 JWT signature")
    header = json.loads(_b64url_decode(header_b64).decode("utf-8"))
    payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    return header, payload


def encode_sec1_p256_pem(private_scalar: int) -> str:
    """Encode a P-256 scalar as SEC1 PEM (helper for stdlib-only tests)."""
    pub_x, pub_y = public_point_from_secret(private_scalar)
    pub_bitstring = b"\x00\x04" + pub_x.to_bytes(32, "big") + pub_y.to_bytes(32, "big")

    def _tlv(tag: int, body: bytes) -> bytes:
        length = len(body)
        if length < 0x80:
            len_bytes = bytes([length])
        else:
            raw_len = length.to_bytes((length.bit_length() + 7) // 8, "big")
            len_bytes = bytes([0x80 | len(raw_len)]) + raw_len
        return bytes([tag]) + len_bytes + body

    seq = _tlv(
        0x30,
        _tlv(0x02, b"\x01")
        + _tlv(0x04, private_scalar.to_bytes(32, "big"))
        + _tlv(0xA0, _tlv(0x06, _OID_SECP256R1))
        + _tlv(0xA1, _tlv(0x03, pub_bitstring)),
    )
    b64 = base64.b64encode(seq).decode("ascii")
    wrapped = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    return f"{_PEM_EC_BEGIN}\n{wrapped}\n{_PEM_EC_END}\n"
