"""Canonical JSON, decimal, alias, and timestamp helpers (pure Python stdlib)."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any

from .errors import AppError

ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
RFC3339_FLEX_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$"
)


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def validate_alias(value: str) -> str:
    if not isinstance(value, str) or not ALIAS_RE.fullmatch(value):
        raise AppError("INVALID_ALIAS", "Account alias must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}.", "Use e.g. default.")
    return value


def dec_str(value: Any) -> str | None:
    if value is None or value == "" or isinstance(value, bool):
        return None
    if isinstance(value, Decimal):
        if not value.is_finite():
            return None
        formatted = format(value, "f")
        return "0" if value == 0 else (formatted.rstrip("0").rstrip(".") if "." in formatted else formatted)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return dec_str(Decimal(str(value)))
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return None
        try:
            d = Decimal(stripped)
            if not d.is_finite():
                return None
            if "e" in stripped.lower():
                return dec_str(d)
            if d == 0:
                return "0"
            return stripped.rstrip("0").rstrip(".") if "." in stripped else stripped
        except InvalidOperation:
            return None
    return None


def positive_decimal(value: Any, field: str) -> str:
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        raise AppError("INVALID_AMOUNT", f"{field} must be a positive decimal string.", f"Provide e.g. '10.00' for {field}.")
    norm = dec_str(str(value).strip())
    if norm is None or Decimal(norm) <= 0:
        raise AppError("INVALID_AMOUNT", f"{field} must be greater than zero.", f"Provide a positive value for {field}.")
    return norm


def normalize_timestamp(value: Any) -> tuple[str | None, str | None]:
    if not isinstance(value, str) or not value:
        return None, None
    match = RFC3339_FLEX_RE.fullmatch(value)
    if not match:
        return None, value
    base, frac, tz = match.groups()
    if int(base[11:13]) > 23 or int(base[14:16]) > 59 or int(base[17:19]) > 59:
        return None, value
    if tz != "Z" and (int(tz[1:3]) > 23 or int(tz[4:6]) > 59):
        return None, value
    iso_in = f"{base}.{frac[:6].ljust(6, '0')}{'+00:00' if tz == 'Z' else tz}" if frac else f"{base}{'+00:00' if tz == 'Z' else tz}"
    try:
        parsed = datetime.fromisoformat(iso_in).astimezone(timezone.utc)
        return parsed.isoformat(timespec="microseconds").replace("+00:00", "Z"), value
    except (ValueError, OverflowError):
        return None, value


def iso_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)
