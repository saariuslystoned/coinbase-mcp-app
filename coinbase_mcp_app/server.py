"""Unified cross-host SEP-1865 MCP App server for Coinbase Advanced Trade Spot (unofficial).

Pure Python 3.12+ standard library over MCP stdio JSON-RPC 2.0.
Works across Antigravity Desktop, Claude Desktop / Claude Code, and ChatGPT / Codex Desktop
using one zero-network HTML card (`ui://coinbase-mcp-app/trade-card.html`), triple `_meta`
resolution, `visibility: ["app"]` model isolation, ephemeral HMAC confirmation tokens stripped
from LLM context, and fail-closed `view`-only CDP ECDSA (`ES256`) key enforcement.

Dry-run by default: never places live orders or touches `trade`/`transfer` keys.
Pass `--demo` (or `COINBASE_MCP_DEMO=1`) to test the full interactive UI with clearly-badged
synthetic data before configuring a view-only Coinbase CDP API key.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Callable, Protocol, TextIO

from . import __version__
from .client import CoinbaseReadOnlyClient, PRODUCT_ID_RE, TransportFn, default_coinbase_transport
from .demo import demo_coinbase_transport
from .errors import AppError
from .jwt_auth import load_cdp_key_file
from .store import ReceiptStore, default_data_dir
from .validation import canonical_json, dec_str, iso_utc, normalize_timestamp, parse_iso, positive_decimal, validate_alias

UI_RESOURCE_URI = "ui://coinbase-mcp-app/trade-card.html"
UI_MIME_TYPE = "text/html;profile=mcp-app"
UI_MAX_BYTES = 10 * 1024 * 1024

SUPPORTED_PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
DEFAULT_PROTOCOL_VERSION = "2025-11-25"

STABLECOIN_SYMBOLS = frozenset({"USDC", "USDT", "USDP", "DAI", "PYUSD", "EURC", "GUSD", "USDS"})
MIN_PREVIEW_TTL_SECONDS = 30
MAX_PREVIEW_TTL_SECONDS = 300
DEFAULT_PREVIEW_TTL_SECONDS = 60
DEFAULT_REFRESH_AFTER_MS = 15000
DEFAULT_MAX_ORDER_USD = Decimal("250")
_DEMO_SCALAR = 0x1A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F809

COINBASE_ORDER_STATUS_MAP = {
    "PENDING": "pending",
    "OPEN": "open",
    "FILLED": "filled",
    "CANCELLED": "cancelled",
    "EXPIRED": "expired",
    "FAILED": "rejected",
    "QUEUED": "pending",
    "CANCEL_QUEUED": "open",
    "EDIT_QUEUED": "open",
    "UNKNOWN_ORDER_STATUS": "unknown",
}


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class ConfirmationTokenCodec:
    """Ephemeral per-process HMAC-SHA256 token codec for _meta['coinbaseApp/confirmationToken']."""

    def __init__(self, secret_key: bytes | None = None) -> None:
        self._secret = secret_key if secret_key is not None else secrets.token_bytes(32)

    def sign(self, claims: dict[str, Any]) -> str:
        payload_b64 = _b64url_encode(canonical_json(claims).encode("utf-8"))
        sig = hmac.new(self._secret, payload_b64.encode("ascii"), hashlib.sha256).digest()
        return f"v1.{payload_b64}.{_b64url_encode(sig)}"

    def verify(self, token: Any) -> dict[str, Any]:
        if not isinstance(token, str) or not token.strip():
            raise AppError("CONFIRMATION_TOKEN_INVALID", "Missing confirmation_token.", "Click Approve inside a rendered confirmation card.", 4)
        parts = token.strip().split(".")
        if len(parts) != 3 or parts[0] != "v1":
            raise AppError("CONFIRMATION_TOKEN_INVALID", "Malformed confirmation_token.", "Request a fresh preview card.", 4)
        _, payload_b64, sig_b64 = parts
        expected = hmac.new(self._secret, payload_b64.encode("ascii"), hashlib.sha256).digest()
        try:
            provided = _b64url_decode(sig_b64)
        except ValueError:
            raise AppError("CONFIRMATION_TOKEN_INVALID", "Malformed token signature.", "Request a fresh preview card.", 4) from None
        if not hmac.compare_digest(expected, provided):
            raise AppError("CONFIRMATION_TOKEN_INVALID", "Invalid confirmation_token HMAC signature.", "Request a fresh preview card.", 4)
        try:
            claims = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise AppError("CONFIRMATION_TOKEN_INVALID", "Corrupt token payload.", "Request a fresh preview card.", 4) from None
        if not isinstance(claims, dict):
            raise AppError("CONFIRMATION_TOKEN_INVALID", "Invalid token claims.", "Request a fresh preview card.", 4)
        return claims


class ExecutionSigner(Protocol):
    mode: str

    def approve_order(self, intent: dict[str, Any], *, now: datetime) -> dict[str, Any]: ...
    def approve_cancel(self, intent: dict[str, Any], *, now: datetime) -> dict[str, Any]: ...


@dataclass(frozen=True)
class DryRunExecutionSigner:
    """Dry-run approval signer: validates caps & preview errors, never submits live Coinbase orders."""

    max_order_usd: Decimal = DEFAULT_MAX_ORDER_USD
    mode: str = "dry_run_preview_only"

    def _check_cap(self, intent: dict[str, Any]) -> None:
        order = intent.get("order") or {}
        preview = intent.get("preview") or {}
        quote_ccy = str(order.get("quote_currency") or "").upper()
        if quote_ccy not in ("USD", "USDC"):
            return
        for raw in (preview.get("order_total"), order.get("amount") if order.get("amount_unit") == "quote_size" else None):
            if raw is None or raw == "":
                continue
            try:
                val = Decimal(str(raw))
            except InvalidOperation:
                continue
            if val > self.max_order_usd:
                raise AppError(
                    "ORDER_CAP_EXCEEDED",
                    f"Order notional {val} {quote_ccy} exceeds local cap ({self.max_order_usd} {quote_ccy}).",
                    "Lower the size or adjust --max-order-usd.",
                    4,
                )
            return

    def approve_order(self, intent: dict[str, Any], *, now: datetime) -> dict[str, Any]:
        self._check_cap(intent)
        preview = intent.get("preview") or {}
        errs = preview.get("errs") or []
        if errs:
            raise AppError(
                "PREVIEW_ERRORS_PRESENT",
                "Cannot approve an order with blocking Coinbase preview errors: " + ", ".join(str(e) for e in errs),
                "Resolve the preview error and request a fresh quote.",
                4,
            )
        return {
            "receipt_version": "1",
            "execution_mode": self.mode,
            "live_order_submitted": False,
            "hardware_signer_status": "DRY_RUN_ONLY_NO_TRADE_KEY_LOADED",
            "intent_id": intent["intent_id"],
            "client_order_id": intent["client_order_id"],
            "intent_sha256": intent["intent_sha256"],
            "approved_at": iso_utc(now),
            "order_summary": intent.get("order"),
            "preview_id": preview.get("preview_id"),
            "order_total": preview.get("order_total"),
            "commission_total": preview.get("commission_total"),
        }

    def approve_cancel(self, intent: dict[str, Any], *, now: datetime) -> dict[str, Any]:
        order = intent.get("order") or {}
        return {
            "receipt_version": "1",
            "execution_mode": self.mode,
            "live_cancel_submitted": False,
            "hardware_signer_status": "DRY_RUN_ONLY_NO_TRADE_KEY_LOADED",
            "intent_id": intent["intent_id"],
            "client_order_id": intent["client_order_id"],
            "order_id": order.get("order_id"),
            "product_id": order.get("product_id"),
            "approved_at": iso_utc(now),
        }


def _build_order_configuration(
    *,
    product_id: str,
    side: str,
    order_type: str,
    quote_size: str | None,
    base_size: str | None,
    limit_price: str | None,
    post_only: bool,
    tif: str | None,
    end_time: str | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    pid = str(product_id or "").strip().upper()
    if not PRODUCT_ID_RE.fullmatch(pid):
        raise AppError("INVALID_PRODUCT", "product_id must be canonical BASE-QUOTE (e.g. BTC-USD or BTC-USDC).", "Pass e.g. BTC-USDC.")
    base_ccy, quote_ccy = pid.split("-", 1)
    side_up = str(side or "").strip().upper()
    if side_up not in ("BUY", "SELL"):
        raise AppError("INVALID_SIDE", "side must be BUY or SELL.", "Pass BUY or SELL.")
    otype = str(order_type or "").strip().upper()
    if otype not in ("MARKET", "LIMIT"):
        raise AppError("INVALID_ORDER_TYPE", "order_type must be MARKET or LIMIT.", "Pass MARKET or LIMIT.")
    has_quote = quote_size is not None and str(quote_size).strip() != ""
    has_base = base_size is not None and str(base_size).strip() != ""
    if has_quote == has_base:
        raise AppError("INVALID_AMOUNT", "Specify exactly one of quote_size or base_size.", "Pass quote_size (e.g. '10.00') or base_size.")

    norm_quote = positive_decimal(quote_size, "quote_size") if has_quote else None
    norm_base = positive_decimal(base_size, "base_size") if has_base else None
    tif_up = (str(tif).strip().upper() if tif else ("IOC" if otype == "MARKET" else "GTC"))

    if otype == "MARKET":
        if limit_price is not None or post_only or end_time is not None:
            raise AppError("INVALID_USAGE", "MARKET orders do not accept limit_price, post_only, or end_time.", "Use order_type=LIMIT for limit orders.")
        if tif_up != "IOC":
            raise AppError("INVALID_USAGE", "MARKET spot orders require tif=IOC.", "Omit tif or pass IOC.")
        cfg: dict[str, Any] = {"market_market_ioc": {"quote_size": norm_quote} if norm_quote else {"base_size": norm_base}}
        norm_limit = None
        norm_end = None
    else:
        if not norm_base:
            raise AppError("INVALID_AMOUNT", "LIMIT orders require base_size.", "Provide base_size and limit_price.")
        norm_limit = positive_decimal(limit_price, "limit_price")
        if tif_up == "GTC":
            cfg = {"limit_limit_gtc": {"base_size": norm_base, "limit_price": norm_limit, "post_only": bool(post_only)}}
            norm_end = None
        elif tif_up == "GTD":
            norm_end, _ = normalize_timestamp(end_time)
            if not norm_end:
                raise AppError("INVALID_TIMESTAMP", "GTD limit orders require an RFC 3339 end_time.", "Provide e.g. 2026-12-01T00:00:00Z.")
            cfg = {"limit_limit_gtd": {"base_size": norm_base, "limit_price": norm_limit, "end_time": norm_end, "post_only": bool(post_only)}}
        elif tif_up == "FOK":
            if post_only:
                raise AppError("INVALID_USAGE", "post_only is unsupported for FOK limit orders.", "Use GTC or GTD with post_only.")
            cfg = {"limit_limit_fok": {"base_size": norm_base, "limit_price": norm_limit}}
            norm_end = None
        else:
            raise AppError("INVALID_USAGE", "LIMIT orders support tif GTC, GTD, or FOK.", "Pass GTC, GTD, or FOK.")

    meta = {
        "product_id": pid,
        "base_currency": base_ccy,
        "quote_currency": quote_ccy,
        "side": side_up,
        "order_type": otype,
        "time_in_force": tif_up,
        "amount": norm_quote if norm_quote else norm_base,
        "amount_unit": "quote_size" if norm_quote else "base_size",
        "amount_currency": quote_ccy if norm_quote else base_ccy,
        "limit_price": norm_limit,
        "post_only": bool(post_only),
        "end_time": norm_end,
    }
    return cfg, meta


def _normalize_order(raw: dict[str, Any]) -> dict[str, Any]:
    raw_status = str(raw.get("status") or "UNKNOWN_ORDER_STATUS")
    created_norm, created_raw = normalize_timestamp(raw.get("created_time"))
    return {
        "order_id": raw.get("order_id"),
        "client_order_id": raw.get("client_order_id"),
        "product_id": raw.get("product_id"),
        "side": raw.get("side"),
        "order_type": raw.get("order_type"),
        "provider_status": raw_status,
        "status": COINBASE_ORDER_STATUS_MAP.get(raw_status, "unknown"),
        "filled_size": dec_str(raw.get("filled_size")),
        "average_filled_price": dec_str(raw.get("average_filled_price")),
        "total_fees": dec_str(raw.get("total_fees")),
        "outstanding_hold_amount": dec_str(raw.get("outstanding_hold_amount")),
        "created_time": created_norm or created_raw,
    }


def _inline_meta() -> dict[str, Any]:
    return {
        "ui": {"resourceUri": UI_RESOURCE_URI, "visibility": ["model", "app"], "prefersBorder": True},
        "ui/resourceUri": UI_RESOURCE_URI,
        "openai/outputTemplate": UI_RESOURCE_URI,
    }


def _panel_meta() -> dict[str, Any]:
    return {
        "ui": {"resourceUri": UI_RESOURCE_URI, "visibility": ["model", "app"], "prefersBorder": True},
        "ui/resourceUri": UI_RESOURCE_URI,
        "openai/outputTemplate": UI_RESOURCE_URI,
        "com.google.antigravity/ui": {
            "entrypoints": [
                {"type": "aux_pane", "title": "Coinbase Spot"},
                {"type": "global", "title": "Coinbase Spot"},
            ]
        },
    }


def _app_only_meta() -> dict[str, Any]:
    return {
        "ui": {"resourceUri": UI_RESOURCE_URI, "visibility": ["app"], "prefersBorder": True},
        "ui/resourceUri": UI_RESOURCE_URI,
        "openai/outputTemplate": UI_RESOURCE_URI,
        "openai/widgetAccessible": True,
    }


def build_tool_definitions() -> list[dict[str, Any]]:
    return [
        {
            "name": "coinbase_balance",
            "title": "Coinbase Spot Balances",
            "description": "Read Coinbase Advanced Trade Spot balances (USD fiat, USDC/stablecoins separately, spot crypto), advisory USD totals, fee tier, and local dry-run receipts via a view-only key.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "account": {"type": "string"},
                    "include_breakdown": {"type": "boolean"},
                },
                "additionalProperties": False,
            },
            "_meta": _panel_meta(),
        },
        {
            "name": "coinbase_quote_preview",
            "title": "Preview Coinbase Spot Market Quote",
            "description": "Preview a Coinbase Advanced Trade spot MARKET buy or sell via a view-only key and render an inline 1-click dry-run confirmation card.",
            "inputSchema": {
                "type": "object",
                "required": ["product_id", "side"],
                "properties": {
                    "product_id": {"type": "string"},
                    "side": {"type": "string", "enum": ["BUY", "SELL", "buy", "sell"]},
                    "quote_size": {"type": "string"},
                    "base_size": {"type": "string"},
                    "account": {"type": "string"},
                    "ttl_seconds": {"type": "integer", "minimum": MIN_PREVIEW_TTL_SECONDS, "maximum": MAX_PREVIEW_TTL_SECONDS},
                },
                "additionalProperties": False,
            },
            "_meta": _inline_meta(),
        },
        {
            "name": "coinbase_order_preview",
            "title": "Preview Coinbase Spot Order",
            "description": "Preview a Coinbase Advanced Trade spot MARKET or LIMIT order via a view-only key and render an inline 1-click dry-run confirmation card.",
            "inputSchema": {
                "type": "object",
                "required": ["product_id", "side", "order_type"],
                "properties": {
                    "product_id": {"type": "string"},
                    "side": {"type": "string", "enum": ["BUY", "SELL", "buy", "sell"]},
                    "order_type": {"type": "string", "enum": ["MARKET", "LIMIT", "market", "limit"]},
                    "quote_size": {"type": "string"},
                    "base_size": {"type": "string"},
                    "limit_price": {"type": "string"},
                    "post_only": {"type": "boolean"},
                    "tif": {"type": "string", "enum": ["GTC", "GTD", "IOC", "FOK", "gtc", "gtd", "ioc", "fok"]},
                    "end_time": {"type": "string"},
                    "account": {"type": "string"},
                    "ttl_seconds": {"type": "integer", "minimum": MIN_PREVIEW_TTL_SECONDS, "maximum": MAX_PREVIEW_TTL_SECONDS},
                },
                "additionalProperties": False,
            },
            "_meta": _inline_meta(),
        },
        {
            "name": "coinbase_order_preview_refresh",
            "title": "Refresh Order Preview (App Only)",
            "description": "App-only quote refresh invoked by the confirmation card.",
            "inputSchema": {
                "type": "object",
                "required": ["confirmation_token"],
                "properties": {"confirmation_token": {"type": "string"}},
                "additionalProperties": False,
            },
            "_meta": _app_only_meta(),
        },
        {
            "name": "coinbase_order_execute",
            "title": "Approve Trade (App Only, Dry Run)",
            "description": "App-only confirmation handler invoked only when the user clicks Approve in the rendered card. Dry-run only; never places live orders.",
            "inputSchema": {
                "type": "object",
                "required": ["confirmation_token"],
                "properties": {"confirmation_token": {"type": "string"}, "check_status": {"type": "boolean"}},
                "additionalProperties": False,
            },
            "_meta": _app_only_meta(),
        },
        {
            "name": "coinbase_order_reject",
            "title": "Reject Trade Preview (App Only)",
            "description": "App-only rejection handler invoked when the user clicks Reject inside the card.",
            "inputSchema": {
                "type": "object",
                "required": ["confirmation_token"],
                "properties": {"confirmation_token": {"type": "string"}},
                "additionalProperties": False,
            },
            "_meta": _app_only_meta(),
        },
        {
            "name": "coinbase_order_cancel_preview",
            "title": "Preview Order Cancel",
            "description": "Inspect a Coinbase order via the view-only key and render an inline 1-click Cancel confirmation card (dry-run only).",
            "inputSchema": {
                "type": "object",
                "required": ["order_id"],
                "properties": {
                    "order_id": {"type": "string"},
                    "account": {"type": "string"},
                    "ttl_seconds": {"type": "integer", "minimum": MIN_PREVIEW_TTL_SECONDS, "maximum": MAX_PREVIEW_TTL_SECONDS},
                },
                "additionalProperties": False,
            },
            "_meta": _inline_meta(),
        },
        {
            "name": "coinbase_order_cancel",
            "title": "Approve Order Cancel (App Only, Dry Run)",
            "description": "App-only cancel confirmation handler (dry-run only; never mutates live Coinbase orders).",
            "inputSchema": {
                "type": "object",
                "required": ["confirmation_token"],
                "properties": {"confirmation_token": {"type": "string"}, "check_status": {"type": "boolean"}},
                "additionalProperties": False,
            },
            "_meta": _app_only_meta(),
        },
        {
            "name": "coinbase_order_status",
            "title": "Check Order or Receipt Status",
            "description": "Check live Coinbase order status by order_id or local dry-run receipt by intent_id / client_order_id.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "order_id": {"type": "string"},
                    "intent_id": {"type": "string"},
                    "client_order_id": {"type": "string"},
                    "account": {"type": "string"},
                },
                "additionalProperties": False,
            },
            "_meta": _inline_meta(),
        },
    ]


def build_resource_definitions() -> list[dict[str, Any]]:
    return [
        {
            "uri": UI_RESOURCE_URI,
            "name": "Coinbase Spot Trade Card",
            "description": "Zero-network SEP-1865 interactive card for Coinbase Advanced Trade Spot balances, previews, and dry-run receipts.",
            "mimeType": UI_MIME_TYPE,
            "_meta": {
                "ui": {"csp": {"connectDomains": [], "resourceDomains": []}, "prefersBorder": True},
                "openai/widgetCSP": {"connect_domains": [], "resource_domains": []},
            },
        }
    ]


class CoinbaseMcpApp:
    def __init__(
        self,
        *,
        data_dir: Path | None = None,
        default_account: str = "default",
        key_file: str | None = None,
        demo_mode: bool = False,
        max_order_usd: Decimal = DEFAULT_MAX_ORDER_USD,
        signer: ExecutionSigner | None = None,
        token_codec: ConfirmationTokenCodec | None = None,
        transport: TransportFn | None = None,
        now_fn: Callable[[], datetime] | None = None,
        html_path: Path | None = None,
    ) -> None:
        validate_alias(default_account)
        self.data_dir = Path(data_dir) if data_dir is not None else default_data_dir()
        self.default_account = default_account
        self.key_file = key_file
        self.demo_mode = bool(demo_mode)
        self.receipt_store = ReceiptStore(self.data_dir)
        self.signer: ExecutionSigner = signer if signer is not None else DryRunExecutionSigner(max_order_usd=max_order_usd)
        self.token_codec = token_codec if token_codec is not None else ConfirmationTokenCodec()
        self._transport: TransportFn = transport if transport is not None else (demo_coinbase_transport if self.demo_mode else default_coinbase_transport)
        self._now_fn = now_fn or (lambda: datetime.now(timezone.utc))
        self._html_path = html_path

    def _now(self) -> datetime:
        return self._now_fn().astimezone(timezone.utc)

    def _account(self, args: dict[str, Any]) -> str:
        raw = args.get("account")
        return validate_alias(raw.strip()) if isinstance(raw, str) and raw.strip() else self.default_account

    def _ttl(self, args: dict[str, Any]) -> int:
        raw = args.get("ttl_seconds")
        if raw is None:
            return DEFAULT_PREVIEW_TTL_SECONDS
        if type(raw) is not int or not MIN_PREVIEW_TTL_SECONDS <= raw <= MAX_PREVIEW_TTL_SECONDS:
            raise AppError("INVALID_DURATION", f"ttl_seconds must be {MIN_PREVIEW_TTL_SECONDS}..{MAX_PREVIEW_TTL_SECONDS}.", "Use e.g. 60.")
        return raw

    def _assert_keys(self, args: dict[str, Any], allowed: frozenset[str], name: str) -> None:
        unknown = sorted(set(args.keys()) - allowed)
        if unknown:
            raise AppError("INVALID_USAGE", f"{name} rejected unexpected arguments: {', '.join(unknown)}.", "Pass only documented arguments.", 4)

    def _resolve_key_file(self) -> str:
        candidates = (
            self.key_file,
            os.environ.get("COINBASE_KEY_FILE"),
            str(Path.home() / ".config/coinbase-mcp-app/view-key.json"),
        )
        for cand in candidates:
            if cand and str(cand).strip() and Path(os.path.expanduser(str(cand).strip())).exists():
                return str(cand).strip()
        raise AppError(
            "COINBASE_KEY_REQUIRED",
            "No view-only Coinbase CDP API key file is configured.",
            "Set COINBASE_KEY_FILE to a mode-0600 ECDSA view-only CDP key outside Git, or launch with --demo to test synthetic data.",
            4,
        )

    def _build_client(self) -> tuple[CoinbaseReadOnlyClient, dict[str, Any]]:
        if self.demo_mode:
            cb = CoinbaseReadOnlyClient(key_name="demo-view-key", private_scalar=_DEMO_SCALAR, transport=self._transport)
        else:
            key_name, scalar = load_cdp_key_file(self._resolve_key_file())
            cb = CoinbaseReadOnlyClient(key_name=key_name, private_scalar=scalar, transport=self._transport)
        perms = cb.verify_view_only()
        return cb, perms

    def _load_ui_html(self) -> str:
        env_override = os.environ.get("COINBASE_MCP_APP_HTML")
        candidate = (
            Path(env_override).expanduser()
            if env_override and env_override.strip()
            else (self._html_path or (Path(__file__).resolve().parent / "ui" / "trade-card.html"))
        )
        if not candidate.is_file():
            raise AppError("MCP_UI_RESOURCE_MISSING", "Bundled trade-card.html not found.", "Rebuild mcp-app-ui/.", 4)
        raw = candidate.read_bytes()
        if not raw or len(raw) > UI_MAX_BYTES:
            raise AppError("MCP_UI_RESOURCE_INVALID", "Bundled trade-card.html exceeds 10 MiB or is empty.", "Rebuild mcp-app-ui/.", 4)
        return raw.decode("utf-8")

    def _tool_balance(self, args: dict[str, Any]) -> dict[str, Any]:
        self._assert_keys(args, frozenset({"account", "include_breakdown"}), "coinbase_balance")
        acct = self._account(args)
        include_breakdown = bool(args.get("include_breakdown", True))
        cb, perms = self._build_client()

        raw_accounts: list[dict[str, Any]] = []
        cursor: str | None = None
        seen: set[str] = set()
        for _ in range(10):
            page = cb.get_accounts_page(limit=250, cursor=cursor)
            raw_accounts.extend(a for a in (page.get("accounts") or []) if isinstance(a, dict))
            if page.get("has_next") is True and isinstance(page.get("cursor"), str) and page["cursor"] and page["cursor"] not in seen:
                seen.add(page["cursor"])
                cursor = page["cursor"]
            else:
                break

        usd_fiat: list[dict[str, Any]] = []
        stablecoins: list[dict[str, Any]] = []
        crypto: list[dict[str, Any]] = []
        for a in raw_accounts:
            ccy = str(a.get("currency") or "").upper()
            atype = str(a.get("type") or "")
            plat = str(a.get("platform") or "ACCOUNT_PLATFORM_CONSUMER")
            avail = dec_str((a.get("available_balance") or {}).get("value")) or "0"
            hold = dec_str((a.get("hold") or {}).get("value")) or "0"
            if plat != "ACCOUNT_PLATFORM_CONSUMER":
                continue
            row = {"currency": ccy, "available_balance": avail, "hold": hold, "account_type": atype, "platform": plat}
            if ccy == "USD" and atype == "ACCOUNT_TYPE_FIAT":
                usd_fiat.append(row)
            elif ccy in STABLECOIN_SYMBOLS:
                if Decimal(avail) > 0 or Decimal(hold) > 0:
                    stablecoins.append(row)
            elif Decimal(avail) > 0 or Decimal(hold) > 0:
                crypto.append(row)

        advisory = None
        if include_breakdown:
            try:
                bd = (cb.get_portfolio_breakdown(perms["portfolio_uuid"]).get("breakdown") or {}).get("portfolio_balances") or {}
                advisory = {
                    "total_balance_usd": dec_str((bd.get("total_balance") or {}).get("value")),
                    "total_cash_equivalent_balance_usd": dec_str((bd.get("total_cash_equivalent_balance") or {}).get("value")),
                    "total_crypto_balance_usd": dec_str((bd.get("total_crypto_balance") or {}).get("value")),
                }
            except AppError:
                advisory = None

        fee_tier = None
        try:
            ft = cb.get_transaction_summary().get("fee_tier") or {}
            if ft:
                fee_tier = {
                    "pricing_tier": ft.get("pricing_tier"),
                    "maker_fee_rate": dec_str(ft.get("maker_fee_rate")),
                    "taker_fee_rate": dec_str(ft.get("taker_fee_rate")),
                }
        except AppError:
            fee_tier = None

        recent = []
        for rec in self.receipt_store.list_recent(acct, limit=6):
            o = (rec.get("payload") or {}).get("order") or {}
            recent.append({
                "intent_id": rec["intent_id"],
                "client_order_id": rec["client_order_id"],
                "state": rec["state"],
                "updated_at": rec["updated_at"],
                "summary": f"{o.get('side', rec['kind'].upper())} {o.get('amount', '')} {o.get('product_id', '')}".strip(),
            })

        structured = {
            "view": "balance_dashboard",
            "demo_mode": self.demo_mode,
            "execution_mode": self.signer.mode,
            "as_of": iso_utc(self._now()),
            "account": {"alias": acct, "portfolio_type": perms["portfolio_type"]},
            "permissions": {"can_view": perms["can_view"], "can_trade": perms["can_trade"], "can_transfer": perms["can_transfer"]},
            "balances": {"usd_fiat": usd_fiat, "stablecoins": stablecoins, "crypto": crypto},
            "advisory_breakdown": advisory,
            "fee_tier": fee_tier,
            "recent_receipts": recent,
            "__refresh_balance_tool": "coinbase_balance",
        }
        usd_val = usd_fiat[0]["available_balance"] if usd_fiat else "0"
        stables = ", ".join(f"{s['currency']}={s['available_balance']}" for s in stablecoins) or "none"
        prefix = "[DEMO SYNTHETIC] " if self.demo_mode else ""
        return {
            "content": [{"type": "text", "text": f"{prefix}Coinbase Spot ({perms['portfolio_type']}, view-only): USD fiat={usd_val}; stablecoins(separate)={stables}; spot crypto={len(crypto)}; advisory USD={(advisory or {}).get('total_balance_usd', 'unavailable')}."}],
            "structuredContent": structured,
            "_meta": {"coinbaseApp/widget": "balance-dashboard"},
            "isError": False,
        }

    def _run_preview(
        self,
        *,
        acct: str,
        product_id: str,
        side: str,
        order_type: str,
        quote_size: str | None,
        base_size: str | None,
        limit_price: str | None,
        post_only: bool,
        tif: str | None,
        end_time: str | None,
        ttl_seconds: int,
        existing_intent: dict[str, Any] | None = None,
        expected_nonce: str | None = None,
    ) -> dict[str, Any]:
        current = self._now()
        cb, perms = self._build_client()
        order_cfg, meta = _build_order_configuration(
            product_id=product_id, side=side, order_type=order_type,
            quote_size=quote_size, base_size=base_size, limit_price=limit_price,
            post_only=post_only, tif=tif, end_time=end_time,
        )
        prod_raw = cb.get_product(meta["product_id"])
        if str(prod_raw.get("product_type") or "") != "SPOT":
            raise AppError("UNSUPPORTED_PRODUCT_TYPE", "Only SPOT products are supported.", "Select a spot pair such as BTC-USD or BTC-USDC.")
        prev_raw = cb.preview_order({"product_id": meta["product_id"], "side": meta["side"], "order_configuration": order_cfg})
        preview = {
            "preview_id": prev_raw.get("preview_id"),
            "order_total": dec_str(prev_raw.get("order_total")),
            "commission_total": dec_str(prev_raw.get("commission_total")),
            "quote_size": dec_str(prev_raw.get("quote_size")),
            "base_size": dec_str(prev_raw.get("base_size")),
            "best_bid": dec_str(prev_raw.get("best_bid")),
            "best_ask": dec_str(prev_raw.get("best_ask")),
            "est_average_filled_price": dec_str(prev_raw.get("est_average_filled_price")),
            "slippage": dec_str(prev_raw.get("slippage")),
            "fill_likelihood": prev_raw.get("fill_likelihood"),
            "errs": [str(e) for e in prev_raw.get("errs", [])] if isinstance(prev_raw.get("errs"), list) else [],
            "warning": [str(w) for w in prev_raw.get("warning", [])] if isinstance(prev_raw.get("warning"), list) else [],
        }

        now_iso = iso_utc(current)
        exp_dt = current + timedelta(seconds=ttl_seconds)
        expires_at = iso_utc(exp_dt)
        intent_id = existing_intent["intent_id"] if existing_intent else str(uuid.uuid4())
        client_order_id = existing_intent["client_order_id"] if existing_intent else str(uuid.uuid4())
        nonce = secrets.token_hex(16)
        bound = {**meta, "portfolio_uuid": perms["portfolio_uuid"], "client_order_id": client_order_id, "expires_at": expires_at, "order_configuration": order_cfg}
        intent_sha256 = hashlib.sha256(canonical_json(bound).encode("utf-8")).hexdigest()

        payload = {
            "intent_id": intent_id,
            "client_order_id": client_order_id,
            "intent_sha256": intent_sha256,
            "demo_mode": self.demo_mode,
            "account": {"alias": acct, "portfolio_type": perms["portfolio_type"]},
            "request_params": {
                "product_id": meta["product_id"], "side": meta["side"], "order_type": meta["order_type"],
                "quote_size": quote_size, "base_size": base_size, "limit_price": limit_price,
                "post_only": post_only, "tif": tif, "end_time": end_time, "ttl_seconds": ttl_seconds,
            },
            "order": meta,
            "preview": preview,
        }
        if existing_intent is None:
            self.receipt_store.save_preview(
                intent_id=intent_id, client_order_id=client_order_id, account_alias=acct, kind="order",
                intent_sha256=intent_sha256, active_nonce=nonce, created_at=now_iso, expires_at=expires_at, payload=payload,
            )
        else:
            assert expected_nonce is not None
            self.receipt_store.refresh_preview(
                intent_id=intent_id, expected_nonce=expected_nonce, new_nonce=nonce,
                new_intent_sha256=intent_sha256, updated_at=now_iso, expires_at=expires_at, payload=payload,
            )

        token = self.token_codec.sign({
            "v": 1, "kind": "order", "intent_id": intent_id, "client_order_id": client_order_id,
            "intent_sha256": intent_sha256, "nonce": nonce, "exp": int(exp_dt.timestamp()),
        })
        prefix = "[DEMO SYNTHETIC] " if self.demo_mode else ""
        return {
            "content": [{"type": "text", "text": f"{prefix}Previewed {meta['side']} {meta['amount']} {meta['amount_currency']} on {meta['product_id']} (est_avg={preview['est_average_filled_price']}, total={preview['order_total']}, fee={preview['commission_total']}, mode={self.signer.mode}). Inline confirmation card rendered; model cannot execute."}],
            "structuredContent": {
                "view": "order_confirm",
                "phase": "preview",
                "demo_mode": self.demo_mode,
                "execution_mode": self.signer.mode,
                "intent_id": intent_id,
                "client_order_id": client_order_id,
                "intent_sha256": intent_sha256,
                "created_at": now_iso,
                "expires_at": expires_at,
                "refresh_after_ms": DEFAULT_REFRESH_AFTER_MS if ttl_seconds >= 30 else 0,
                "account": {"alias": acct, "portfolio_type": perms["portfolio_type"]},
                "order": meta,
                "preview": preview,
                "__confirm_tool": "coinbase_order_execute",
                "__reject_tool": "coinbase_order_reject",
                "__refresh_tool": "coinbase_order_preview_refresh",
                "__status_tool": "coinbase_order_status",
            },
            "_meta": {"coinbaseApp/confirmationToken": token, "coinbaseApp/widget": "order-confirm"},
            "isError": False,
        }

    def _tool_quote_preview(self, args: dict[str, Any]) -> dict[str, Any]:
        self._assert_keys(args, frozenset({"product_id", "side", "quote_size", "base_size", "account", "ttl_seconds"}), "coinbase_quote_preview")
        return self._run_preview(
            acct=self._account(args), product_id=str(args.get("product_id") or ""), side=str(args.get("side") or ""),
            order_type="MARKET", quote_size=args.get("quote_size"), base_size=args.get("base_size"),
            limit_price=None, post_only=False, tif="IOC", end_time=None, ttl_seconds=self._ttl(args),
        )

    def _tool_order_preview(self, args: dict[str, Any]) -> dict[str, Any]:
        self._assert_keys(args, frozenset({"product_id", "side", "order_type", "quote_size", "base_size", "limit_price", "post_only", "tif", "end_time", "account", "ttl_seconds"}), "coinbase_order_preview")
        return self._run_preview(
            acct=self._account(args), product_id=str(args.get("product_id") or ""), side=str(args.get("side") or ""),
            order_type=str(args.get("order_type") or ""), quote_size=args.get("quote_size"), base_size=args.get("base_size"),
            limit_price=args.get("limit_price"), post_only=bool(args.get("post_only", False)),
            tif=args.get("tif"), end_time=args.get("end_time"), ttl_seconds=self._ttl(args),
        )

    def _tool_refresh(self, args: dict[str, Any]) -> dict[str, Any]:
        self._assert_keys(args, frozenset({"confirmation_token"}), "coinbase_order_preview_refresh")
        claims = self.token_codec.verify(args.get("confirmation_token"))
        if claims.get("kind") != "order":
            raise AppError("CONFIRMATION_TOKEN_INVALID", "Token is not an order preview token.", "Request a fresh preview.", 4)
        rec = self.receipt_store.get_by_intent_id(str(claims.get("intent_id") or ""))
        if rec is None:
            raise AppError("INTENT_NOT_FOUND", "Unknown preview intent.", "Request a fresh preview.", 3)
        req = (rec.get("payload") or {}).get("request_params") or {}
        return self._run_preview(
            acct=rec["account_alias"], product_id=str(req.get("product_id") or ""), side=str(req.get("side") or ""),
            order_type=str(req.get("order_type") or "MARKET"), quote_size=req.get("quote_size"), base_size=req.get("base_size"),
            limit_price=req.get("limit_price"), post_only=bool(req.get("post_only", False)), tif=req.get("tif"),
            end_time=req.get("end_time"), ttl_seconds=int(req.get("ttl_seconds") or DEFAULT_PREVIEW_TTL_SECONDS),
            existing_intent=rec, expected_nonce=str(claims.get("nonce") or ""),
        )

    def _render_final_order(self, rec: dict[str, Any], *, phase: str, idempotent: bool) -> dict[str, Any]:
        payload = rec.get("payload") or {}
        order = payload.get("order") or {}
        return {
            "content": [{"type": "text", "text": f"Dry-run approval recorded for {order.get('side')} {order.get('product_id')} (client_order_id={rec['client_order_id']}; no live order placed)." if phase == "approved_dry_run" else f"Order draft rejected (client_order_id={rec['client_order_id']})."}],
            "structuredContent": {
                "view": "order_confirm", "phase": phase, "idempotent_replay": idempotent,
                "demo_mode": bool(payload.get("demo_mode", self.demo_mode)), "execution_mode": self.signer.mode,
                "intent_id": rec["intent_id"], "client_order_id": rec["client_order_id"],
                "intent_sha256": rec["intent_sha256"], "expires_at": rec["expires_at"],
                "account": payload.get("account"), "order": order, "preview": payload.get("preview"), "receipt": rec.get("receipt"),
            },
            "isError": False,
        }

    def _tool_execute(self, args: dict[str, Any]) -> dict[str, Any]:
        self._assert_keys(args, frozenset({"confirmation_token", "check_status"}), "coinbase_order_execute")
        claims = self.token_codec.verify(args.get("confirmation_token"))
        if claims.get("kind") != "order":
            raise AppError("CONFIRMATION_TOKEN_INVALID", "Token is not an order token.", "Use the order card.", 4)
        check_status = bool(args.get("check_status", False))
        current = self._now()
        rec = self.receipt_store.get_by_intent_id(str(claims.get("intent_id") or ""))
        if rec is None:
            raise AppError("INTENT_NOT_FOUND", "Unknown preview intent.", "Request a fresh preview.", 3)
        if check_status:
            if rec["state"] == "DRY_RUN_APPROVED" and rec["consumed_nonce"] == claims.get("nonce"):
                return self._render_final_order(rec, phase="approved_dry_run", idempotent=True)
            if rec["state"] == "REJECTED":
                return self._render_final_order(rec, phase="rejected", idempotent=True)
            return {
                "content": [{"type": "text", "text": f"Intent {rec['intent_id']} has not been approved yet (state={rec['state']})."}],
                "structuredContent": {
                    "view": "order_confirm", "phase": "preview" if parse_iso(rec["expires_at"]) > current else "expired",
                    "demo_mode": self.demo_mode, "execution_mode": self.signer.mode, "intent_id": rec["intent_id"],
                    "client_order_id": rec["client_order_id"], "intent_sha256": rec["intent_sha256"],
                    "expires_at": rec["expires_at"], "order": rec["payload"].get("order"), "preview": rec["payload"].get("preview"),
                },
                "isError": False,
            }
        if int(claims.get("exp", 0)) < int(current.timestamp()) or parse_iso(rec["expires_at"]) <= current:
            raise AppError("CONFIRMATION_TOKEN_EXPIRED", "Quote preview expired before approval.", "Request a fresh quote.", 4)
        receipt = self.signer.approve_order(rec["payload"], now=current)
        finalized, already = self.receipt_store.finalize_once(
            intent_id=rec["intent_id"], expected_nonce=str(claims.get("nonce") or ""),
            expected_sha256=str(claims.get("intent_sha256") or ""), new_state="DRY_RUN_APPROVED",
            updated_at=iso_utc(current), receipt=receipt, check_status=False,
        )
        return self._render_final_order(finalized, phase="approved_dry_run", idempotent=already)

    def _tool_reject(self, args: dict[str, Any]) -> dict[str, Any]:
        self._assert_keys(args, frozenset({"confirmation_token"}), "coinbase_order_reject")
        claims = self.token_codec.verify(args.get("confirmation_token"))
        current = self._now()
        rec = self.receipt_store.get_by_intent_id(str(claims.get("intent_id") or ""))
        if rec is None:
            raise AppError("INTENT_NOT_FOUND", "Unknown preview intent.", "Nothing to reject.", 3)
        receipt = {"receipt_version": "1", "execution_mode": self.signer.mode, "rejected_at": iso_utc(current), "intent_id": rec["intent_id"], "client_order_id": rec["client_order_id"]}
        finalized, _ = self.receipt_store.finalize_once(
            intent_id=rec["intent_id"], expected_nonce=str(claims.get("nonce") or ""),
            expected_sha256=str(claims.get("intent_sha256") or ""), new_state="REJECTED",
            updated_at=iso_utc(current), receipt=receipt, check_status=False,
        )
        if finalized["kind"] == "cancel":
            return {
                "content": [{"type": "text", "text": f"Cancel dismissed for intent {finalized['intent_id']}; order untouched."}],
                "structuredContent": {"view": "cancel_confirm", "phase": "rejected", "demo_mode": self.demo_mode, "execution_mode": self.signer.mode, "intent_id": finalized["intent_id"], "order": finalized["payload"].get("order"), "receipt": receipt},
                "isError": False,
            }
        return self._render_final_order(finalized, phase="rejected", idempotent=False)

    def _tool_cancel_preview(self, args: dict[str, Any]) -> dict[str, Any]:
        self._assert_keys(args, frozenset({"order_id", "account", "ttl_seconds"}), "coinbase_order_cancel_preview")
        acct = self._account(args)
        order_id = str(args.get("order_id") or "").strip()
        if not order_id:
            raise AppError("INVALID_ORDER_ID", "order_id is required.", "Provide a Coinbase order_id.")
        ttl_seconds = self._ttl(args)
        current = self._now()
        cb, perms = self._build_client()
        raw = cb.get_order(order_id)
        norm = _normalize_order(raw.get("order") if isinstance(raw.get("order"), dict) else raw)

        now_iso = iso_utc(current)
        exp_dt = current + timedelta(seconds=ttl_seconds)
        expires_at = iso_utc(exp_dt)
        intent_id = str(uuid.uuid4())
        client_order_id = f"cancel-{uuid.uuid4()}"
        nonce = secrets.token_hex(16)
        intent_sha256 = hashlib.sha256(canonical_json({"kind": "cancel", "order_id": norm["order_id"] or order_id, "expires_at": expires_at}).encode("utf-8")).hexdigest()
        payload = {"intent_id": intent_id, "client_order_id": client_order_id, "intent_sha256": intent_sha256, "demo_mode": self.demo_mode, "account": {"alias": acct, "portfolio_type": perms["portfolio_type"]}, "order": norm}
        self.receipt_store.save_preview(
            intent_id=intent_id, client_order_id=client_order_id, account_alias=acct, kind="cancel",
            intent_sha256=intent_sha256, active_nonce=nonce, created_at=now_iso, expires_at=expires_at, payload=payload,
        )
        token = self.token_codec.sign({"v": 1, "kind": "cancel", "intent_id": intent_id, "client_order_id": client_order_id, "intent_sha256": intent_sha256, "nonce": nonce, "exp": int(exp_dt.timestamp())})
        return {
            "content": [{"type": "text", "text": f"Prepared cancel confirmation card for {norm['order_id'] or order_id} ({norm['side']} {norm['product_id']}, mode={self.signer.mode}). No live cancel sent."}],
            "structuredContent": {
                "view": "cancel_confirm", "phase": "preview", "demo_mode": self.demo_mode, "execution_mode": self.signer.mode,
                "intent_id": intent_id, "intent_sha256": intent_sha256, "expires_at": expires_at, "order": norm,
                "__confirm_tool": "coinbase_order_cancel", "__reject_tool": "coinbase_order_reject",
            },
            "_meta": {"coinbaseApp/confirmationToken": token, "coinbaseApp/widget": "cancel-confirm"},
            "isError": False,
        }

    def _tool_cancel(self, args: dict[str, Any]) -> dict[str, Any]:
        self._assert_keys(args, frozenset({"confirmation_token", "check_status"}), "coinbase_order_cancel")
        claims = self.token_codec.verify(args.get("confirmation_token"))
        if claims.get("kind") != "cancel":
            raise AppError("CONFIRMATION_TOKEN_INVALID", "Token is not a cancel token.", "Use the cancel card.", 4)
        check_status = bool(args.get("check_status", False))
        current = self._now()
        rec = self.receipt_store.get_by_intent_id(str(claims.get("intent_id") or ""))
        if rec is None:
            raise AppError("INTENT_NOT_FOUND", "Unknown cancel intent.", "Request a fresh cancel preview.", 3)
        if check_status:
            if rec["state"] == "DRY_RUN_CANCEL_APPROVED" and rec["consumed_nonce"] == claims.get("nonce"):
                return {
                    "content": [{"type": "text", "text": f"Dry-run cancel already recorded for intent {rec['intent_id']}."}],
                    "structuredContent": {"view": "cancel_confirm", "phase": "cancel_approved_dry_run", "idempotent_replay": True, "demo_mode": self.demo_mode, "execution_mode": self.signer.mode, "intent_id": rec["intent_id"], "order": rec["payload"].get("order"), "receipt": rec.get("receipt")},
                    "isError": False,
                }
            return {
                "content": [{"type": "text", "text": f"Cancel intent {rec['intent_id']} has not been confirmed yet (state={rec['state']})."}],
                "structuredContent": {"view": "cancel_confirm", "phase": "preview" if parse_iso(rec["expires_at"]) > current else "expired", "demo_mode": self.demo_mode, "execution_mode": self.signer.mode, "intent_id": rec["intent_id"], "order": rec["payload"].get("order")},
                "isError": False,
            }
        if int(claims.get("exp", 0)) < int(current.timestamp()) or parse_iso(rec["expires_at"]) <= current:
            raise AppError("CONFIRMATION_TOKEN_EXPIRED", "Cancel preview expired.", "Request a fresh cancel preview.", 4)
        receipt = self.signer.approve_cancel(rec["payload"], now=current)
        finalized, already = self.receipt_store.finalize_once(
            intent_id=rec["intent_id"], expected_nonce=str(claims.get("nonce") or ""),
            expected_sha256=str(claims.get("intent_sha256") or ""), new_state="DRY_RUN_CANCEL_APPROVED",
            updated_at=iso_utc(current), receipt=receipt, check_status=False,
        )
        return {
            "content": [{"type": "text", "text": f"Dry-run cancel recorded for {receipt.get('order_id')} (no live cancel sent)."}],
            "structuredContent": {"view": "cancel_confirm", "phase": "cancel_approved_dry_run", "idempotent_replay": already, "demo_mode": self.demo_mode, "execution_mode": self.signer.mode, "intent_id": finalized["intent_id"], "order": finalized["payload"].get("order"), "receipt": receipt},
            "isError": False,
        }

    def _tool_status(self, args: dict[str, Any]) -> dict[str, Any]:
        self._assert_keys(args, frozenset({"order_id", "intent_id", "client_order_id", "account"}), "coinbase_order_status")
        order_id = str(args.get("order_id") or "").strip()
        intent_id = str(args.get("intent_id") or "").strip()
        client_order_id = str(args.get("client_order_id") or "").strip()
        if not any((order_id, intent_id, client_order_id)):
            raise AppError("INVALID_USAGE", "Provide order_id, intent_id, or client_order_id.", "Pass one identifier.")
        if order_id:
            cb, _ = self._build_client()
            raw = cb.get_order(order_id)
            norm = _normalize_order(raw.get("order") if isinstance(raw.get("order"), dict) else raw)
            return {
                "content": [{"type": "text", "text": f"Coinbase order {norm['order_id'] or order_id}: {norm['provider_status']} ({norm['side']} {norm['product_id']})."}],
                "structuredContent": {"view": "order_status", "demo_mode": self.demo_mode, "lookup_source": "coinbase_live", "order": norm, "__status_tool": "coinbase_order_status"},
                "isError": False,
            }
        rec = self.receipt_store.get_by_intent_id(intent_id) if intent_id else self.receipt_store.get_by_client_order_id(client_order_id)
        if rec is None:
            raise AppError("INTENT_NOT_FOUND", "No local receipt matched.", "Verify intent_id or client_order_id.", 3)
        return {
            "content": [{"type": "text", "text": f"Local intent {rec['intent_id']} (client_order_id={rec['client_order_id']}): state={rec['state']}."}],
            "structuredContent": {
                "view": "order_status", "demo_mode": self.demo_mode, "lookup_source": "local_receipt",
                "receipt": {"intent_id": rec["intent_id"], "client_order_id": rec["client_order_id"], "state": rec["state"], "execution_mode": (rec.get("receipt") or {}).get("execution_mode", self.signer.mode), "updated_at": rec["updated_at"]},
                "__status_tool": "coinbase_order_status",
            },
            "isError": False,
        }

    def call_tool(self, name: str, arguments: dict[str, Any] | None) -> dict[str, Any]:
        args = arguments if isinstance(arguments, dict) else {}
        handlers = {
            "coinbase_balance": self._tool_balance,
            "coinbase_quote_preview": self._tool_quote_preview,
            "coinbase_order_preview": self._tool_order_preview,
            "coinbase_order_preview_refresh": self._tool_refresh,
            "coinbase_order_execute": self._tool_execute,
            "coinbase_order_reject": self._tool_reject,
            "coinbase_order_cancel_preview": self._tool_cancel_preview,
            "coinbase_order_cancel": self._tool_cancel,
            "coinbase_order_status": self._tool_status,
        }
        handler = handlers.get(name)
        if handler is None:
            raise AppError("UNKNOWN_TOOL", f"Unknown tool: {name}", "Call tools/list.")
        try:
            return handler(args)
        except AppError as exc:
            return {
                "content": [{"type": "text", "text": f"[{exc.code}] {exc.message} Next: {exc.action}"}],
                "structuredContent": {"error_code": exc.code, "error_message": exc.message, "next_step": exc.action},
                "isError": True,
            }

    def handle_jsonrpc(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        if "id" not in msg:
            return None
        req_id = msg.get("id")
        method = msg.get("method")
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        if not isinstance(method, str):
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32600, "message": "Invalid Request"}}
        if method == "initialize":
            req_ver = params.get("protocolVersion")
            chosen = req_ver if isinstance(req_ver, str) and req_ver in SUPPORTED_PROTOCOL_VERSIONS else DEFAULT_PROTOCOL_VERSION
            return {
                "jsonrpc": "2.0", "id": req_id,
                "result": {
                    "protocolVersion": chosen,
                    "capabilities": {
                        "tools": {"listChanged": False},
                        "resources": {"subscribe": False, "listChanged": False},
                        "extensions": {"io.modelcontextprotocol/ui": {"mimeTypes": [UI_MIME_TYPE]}},
                    },
                    "serverInfo": {"name": "coinbase-mcp-app", "version": __version__},
                },
            }
        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": build_tool_definitions()}}
        if method == "tools/call":
            tname = params.get("name")
            targs = params.get("arguments")
            if not isinstance(tname, str) or not tname:
                return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Missing tool name"}}
            if targs is not None and not isinstance(targs, dict):
                return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "arguments must be an object"}}
            try:
                return {"jsonrpc": "2.0", "id": req_id, "result": self.call_tool(tname, targs)}
            except AppError as exc:
                return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": f"{exc.code}: {exc.message}"}}
        if method == "resources/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"resources": build_resource_definitions()}}
        if method == "resources/templates/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"resourceTemplates": []}}
        if method == "resources/read":
            if params.get("uri") != UI_RESOURCE_URI:
                return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32002, "message": f"Unknown resource URI: {params.get('uri')}"}}
            try:
                html = self._load_ui_html()
            except AppError as exc:
                return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32603, "message": exc.message}}
            return {
                "jsonrpc": "2.0", "id": req_id,
                "result": {
                    "contents": [{
                        "uri": UI_RESOURCE_URI, "mimeType": UI_MIME_TYPE, "text": html,
                        "_meta": {
                            "ui": {"csp": {"connectDomains": [], "resourceDomains": []}, "prefersBorder": True},
                            "openai/widgetCSP": {"connect_domains": [], "resource_domains": []},
                        },
                    }]
                },
            }
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}

    def serve_stdio(self, stdin: TextIO | None = None, stdout: TextIO | None = None) -> int:
        in_s = stdin if stdin is not None else sys.stdin
        out_s = stdout if stdout is not None else sys.stdout
        for raw_line in in_s:
            line = raw_line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                out_s.write(json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}) + "\n")
                out_s.flush()
                continue
            if not isinstance(msg, dict):
                out_s.write(json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}) + "\n")
                out_s.flush()
                continue
            resp = self.handle_jsonrpc(msg)
            if resp is not None:
                out_s.write(json.dumps(resp, separators=(",", ":"), ensure_ascii=False) + "\n")
                out_s.flush()
        return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="coinbase-mcp-app",
        description="Unofficial cross-host SEP-1865 MCP App for Coinbase Advanced Trade Spot (view-only + dry-run).",
    )
    parser.add_argument("--data-dir", metavar="DIR", help="Private 0700 receipt storage directory.")
    parser.add_argument("--account", default=os.environ.get("COINBASE_MCP_ACCOUNT", "default"), help="Account alias.")
    parser.add_argument("--key-file", metavar="PATH", help="Mode-0600 view-only Coinbase ECDSA CDP JSON key outside Git.")
    parser.add_argument("--demo", action="store_true", help="Run with clearly-badged synthetic demo data (no Coinbase API key required).")
    parser.add_argument("--max-order-usd", default=os.environ.get("COINBASE_MCP_MAX_ORDER_USD", "250"), help="Local notional cap in USD/USDC.")
    parser.add_argument("--version", action="version", version=f"coinbase-mcp-app {__version__}")
    ns = parser.parse_args(argv)
    demo_env = str(os.environ.get("COINBASE_MCP_DEMO", "")).strip().lower() in ("1", "true", "yes")
    try:
        cap = Decimal(str(ns.max_order_usd).strip())
        if not cap.is_finite() or cap <= 0:
            raise AppError("INVALID_USAGE", "--max-order-usd must be positive.", "Pass e.g. 250.")
        app = CoinbaseMcpApp(
            data_dir=Path(ns.data_dir) if ns.data_dir else None,
            default_account=ns.account,
            key_file=ns.key_file,
            demo_mode=bool(ns.demo or demo_env),
            max_order_usd=cap,
        )
        return app.serve_stdio()
    except (AppError, InvalidOperation) as exc:
        print(f"coinbase-mcp-app error: {exc}", file=sys.stderr)
        return getattr(exc, "exit_code", 2)


if __name__ == "__main__":
    raise SystemExit(main())
