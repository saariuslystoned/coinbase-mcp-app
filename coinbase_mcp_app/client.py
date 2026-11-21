"""Read/preview-only Coinbase Advanced Trade REST client (https://api.coinbase.com).

Hardcodes host api.coinbase.com and a strict read/preview endpoint allowlist.
Write endpoints (POST /orders, edit, cancel, convert, transfer) are structurally
forbidden. Every authenticated session must pass GET /key_permissions fail-closed
first (can_view=True, can_trade=False, can_transfer=False, valid portfolio_uuid).
"""
from __future__ import annotations

import http.client
import json
import re
import urllib.parse
from contextlib import closing
from decimal import Decimal
from typing import Any, Callable

from .jwt_auth import COINBASE_HOST, build_cdp_es256_jwt
from .errors import AppError

MAX_RESPONSE_BYTES = 4 * 1024 * 1024  # 4 MiB per page
DEFAULT_TIMEOUT_SECONDS = 15.0

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
PRODUCT_ID_RE = re.compile(r"^[A-Z0-9]{1,20}-[A-Z0-9]{1,20}$")
ORDER_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

READ_PREVIEW_ALLOWLIST = frozenset(
    {
        ("GET", "/api/v3/brokerage/key_permissions"),
        ("GET", "/api/v3/brokerage/time"),
        ("GET", "/api/v3/brokerage/portfolios"),
        ("GET", "/api/v3/brokerage/portfolios/{portfolio_uuid}"),
        ("GET", "/api/v3/brokerage/accounts"),
        ("GET", "/api/v3/brokerage/orders/historical/batch"),
        ("GET", "/api/v3/brokerage/orders/historical/{order_id}"),
        ("GET", "/api/v3/brokerage/orders/historical/fills"),
        ("GET", "/api/v3/brokerage/products/{product_id}"),
        ("GET", "/api/v3/brokerage/best_bid_ask"),
        ("GET", "/api/v3/brokerage/transaction_summary"),
        ("POST", "/api/v3/brokerage/orders/preview"),
    }
)

PUBLIC_ENDPOINTS = frozenset({("GET", "/api/v3/brokerage/time")})

TransportFn = Callable[
    [str, str, dict[str, str], bytes | None, float],
    tuple[int, bytes],
]


def default_coinbase_transport(
    method: str,
    request_target: str,
    headers: dict[str, str],
    body: bytes | None,
    timeout: float,
) -> tuple[int, bytes]:
    """Fixed HTTPS transport to api.coinbase.com with no redirects or proxy overrides."""
    if not request_target.startswith("/api/v3/brokerage/"):
        raise AppError(
            "COINBASE_WRITE_FORBIDDEN",
            "Refused disallowed Coinbase request path.",
            "Only documented read/preview brokerage paths are permitted.",
            4,
        )
    with closing(http.client.HTTPSConnection(COINBASE_HOST, timeout=timeout)) as conn:
        try:
            conn.request(method, request_target, body=body, headers=headers)
            with conn.getresponse() as resp:
                raw = resp.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise AppError(
                        "COINBASE_RESPONSE_TOO_LARGE",
                        "Coinbase API response exceeded the 4 MiB safety limit.",
                        "Narrow the query or paginate with smaller limits.",
                        4,
                    )
                return int(resp.status), raw
        except AppError:
            raise
        except (OSError, http.client.HTTPException, TimeoutError):
            raise AppError(
                "COINBASE_SOURCE_UNAVAILABLE",
                "Could not reach Coinbase Advanced Trade API.",
                "Check network connectivity and IP allowlist, then retry.",
                4,
            ) from None


def _decode_json_body(raw: bytes, *, parse_float_as_decimal: bool = False) -> Any:
    try:
        text = raw.decode("utf-8")
        if parse_float_as_decimal:
            return json.loads(text, parse_float=Decimal)
        return json.loads(text)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise AppError(
            "COINBASE_INVALID_RESPONSE",
            "Coinbase API returned a non-JSON or malformed response.",
            "Retry later; do not treat malformed responses as empty balances or orders.",
            4,
        ) from None


class CoinbaseReadOnlyClient:
    """Enforces hardcoded api.coinbase.com read/preview endpoints and view-only preflight."""

    def __init__(
        self,
        *,
        key_name: str,
        private_scalar: int,
        transport: TransportFn = default_coinbase_transport,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._key_name = key_name
        self._private_scalar = private_scalar
        self._transport = transport
        self._timeout = timeout
        self._verified_permissions: dict[str, Any] | None = None

    def request_json(
        self,
        *,
        method: str,
        path_template: str,
        concrete_path: str,
        query: list[tuple[str, str]] | dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        parse_float_as_decimal: bool = False,
        require_verified_view_only: bool = True,
    ) -> dict[str, Any]:
        method_up = method.upper()
        if (method_up, path_template) not in READ_PREVIEW_ALLOWLIST:
            raise AppError(
                "COINBASE_WRITE_FORBIDDEN",
                "This view-only adapter forbids Coinbase write, trade, convert, and transfer endpoints.",
                "Write/trade endpoints are structurally blocked in view-only mode.",
                4,
            )
        if not concrete_path.startswith("/api/v3/brokerage/") or "?" in concrete_path or ".." in concrete_path:
            raise AppError(
                "COINBASE_INVALID_PATH",
                "Invalid Coinbase API path.",
                "Use documented brokerage endpoints only.",
                4,
            )
        is_public = (method_up, path_template) in PUBLIC_ENDPOINTS
        if require_verified_view_only and not is_public and path_template != "/api/v3/brokerage/key_permissions":
            if self._verified_permissions is None:
                self.verify_view_only()

        headers = {
            "Accept": "application/json",
            "User-Agent": "coinbase-mcp-app/0.1",
        }
        if not is_public:
            token = build_cdp_es256_jwt(
                key_name=self._key_name,
                private_scalar=self._private_scalar,
                method=method_up,
                request_path=concrete_path,
            )
            headers["Authorization"] = f"Bearer {token}"

        raw_body: bytes | None = None
        if json_body is not None:
            raw_body = json.dumps(json_body, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
            headers["Content-Type"] = "application/json"

        request_target = concrete_path
        if query:
            request_target = f"{concrete_path}?{urllib.parse.urlencode(query, doseq=True)}"

        status, raw = self._transport(method_up, request_target, headers, raw_body, self._timeout)
        if status in (401, 403):
            raise AppError(
                "COINBASE_AUTH_REJECTED",
                "Coinbase rejected the CDP API key or permissions (HTTP 401/403).",
                "Verify the ECDSA (ES256) view-only key, portfolio scope, and IP allowlist.",
                4,
            )
        if status == 404:
            raise AppError(
                "COINBASE_NOT_FOUND",
                "Coinbase API reported the requested resource was not found (HTTP 404).",
                "Verify the product ID, order ID, or portfolio scope.",
                3,
            )
        if status == 429:
            raise AppError(
                "COINBASE_RATE_LIMITED",
                "Coinbase API rate limit reached (HTTP 429).",
                "Wait briefly and retry the read-only command.",
                4,
            )
        if status != 200:
            raise AppError(
                "COINBASE_SOURCE_UNAVAILABLE",
                f"Coinbase API returned unexpected HTTP {status}.",
                "Check request parameters and retry when Coinbase API is available.",
                4,
            )

        parsed = _decode_json_body(raw, parse_float_as_decimal=parse_float_as_decimal)
        if not isinstance(parsed, dict):
            raise AppError(
                "COINBASE_INVALID_RESPONSE",
                "Coinbase API returned an unexpected JSON root type.",
                "Retry later; expected a JSON object.",
                4,
            )
        return parsed

    def verify_view_only(self) -> dict[str, Any]:
        """Fail closed unless key is strictly view-only with a valid single portfolio UUID."""
        data = self.request_json(
            method="GET",
            path_template="/api/v3/brokerage/key_permissions",
            concrete_path="/api/v3/brokerage/key_permissions",
            require_verified_view_only=False,
        )
        can_view = data.get("can_view")
        can_trade = data.get("can_trade")
        can_transfer = data.get("can_transfer")
        portfolio_uuid = data.get("portfolio_uuid")
        portfolio_type = data.get("portfolio_type")

        if can_trade is not False or can_transfer is not False:
            raise AppError(
                "CREDENTIAL_OVERPRIVILEGED",
                "Refused Coinbase key with trade or transfer permissions enabled (or unverifiable).",
                "Use a dedicated view-only CDP ECDSA key (can_view=true, can_trade=false, can_transfer=false).",
                4,
            )
        if can_view is not True:
            raise AppError(
                "COINBASE_AUTH_REJECTED",
                "Coinbase key does not have view permission enabled.",
                "Use a view-only CDP ECDSA key.",
                4,
            )
        if not isinstance(portfolio_uuid, str) or not UUID_RE.fullmatch(portfolio_uuid):
            raise AppError(
                "COINBASE_PORTFOLIO_AMBIGUOUS",
                "Coinbase key_permissions did not return a single valid portfolio UUID.",
                "Scope the view-only CDP key to one explicit retail spot portfolio.",
                4,
            )
        verified = {
            "can_view": True,
            "can_trade": False,
            "can_transfer": False,
            "portfolio_uuid": portfolio_uuid,
            "portfolio_type": portfolio_type if isinstance(portfolio_type, str) else "UNDEFINED",
        }
        self._verified_permissions = verified
        return dict(verified)

    def get_server_time(self) -> dict[str, Any]:
        return self.request_json(
            method="GET",
            path_template="/api/v3/brokerage/time",
            concrete_path="/api/v3/brokerage/time",
            require_verified_view_only=False,
        )

    def get_accounts_page(self, *, limit: int = 250, cursor: str | None = None) -> dict[str, Any]:
        query: dict[str, str] = {"limit": str(limit)}
        if cursor:
            query["cursor"] = cursor
        return self.request_json(
            method="GET",
            path_template="/api/v3/brokerage/accounts",
            concrete_path="/api/v3/brokerage/accounts",
            query=query,
        )

    def get_portfolio_breakdown(self, portfolio_uuid: str) -> dict[str, Any]:
        if not UUID_RE.fullmatch(portfolio_uuid):
            raise AppError("COINBASE_INVALID_PATH", "Invalid portfolio UUID.", "Verify key_permissions portfolio scope.", 4)
        return self.request_json(
            method="GET",
            path_template="/api/v3/brokerage/portfolios/{portfolio_uuid}",
            concrete_path=f"/api/v3/brokerage/portfolios/{portfolio_uuid}",
            parse_float_as_decimal=True,
        )

    def get_transaction_summary(self, *, product_type: str = "SPOT") -> dict[str, Any]:
        return self.request_json(
            method="GET",
            path_template="/api/v3/brokerage/transaction_summary",
            concrete_path="/api/v3/brokerage/transaction_summary",
            query={"product_type": product_type},
        )

    def get_product(self, product_id: str) -> dict[str, Any]:
        if not PRODUCT_ID_RE.fullmatch(product_id):
            raise AppError(
                "INVALID_PRODUCT",
                "Product ID must be a canonical Coinbase spot pair such as BTC-USD or BTC-USDC.",
                "Use UPPERCASE BASE-QUOTE format.",
            )
        return self.request_json(
            method="GET",
            path_template="/api/v3/brokerage/products/{product_id}",
            concrete_path=f"/api/v3/brokerage/products/{product_id}",
        )

    def get_orders_batch_page(
        self,
        *,
        limit: int = 100,
        cursor: str | None = None,
        order_placement_source: str | None = None,
        product_ids: list[str] | None = None,
        order_status: list[str] | None = None,
    ) -> dict[str, Any]:
        params: list[tuple[str, str]] = [("limit", str(limit))]
        if cursor:
            params.append(("cursor", cursor))
        if order_placement_source:
            params.append(("order_placement_source", order_placement_source))
        for pid in product_ids or ():
            params.append(("product_ids", pid))
        for st in order_status or ():
            params.append(("order_status", st))
        return self.request_json(
            method="GET",
            path_template="/api/v3/brokerage/orders/historical/batch",
            concrete_path="/api/v3/brokerage/orders/historical/batch",
            query=params,
        )

    def get_order(self, order_id: str) -> dict[str, Any]:
        if not isinstance(order_id, str) or not ORDER_ID_RE.fullmatch(order_id):
            raise AppError(
                "INVALID_ORDER_ID",
                "Order ID contains unsupported characters.",
                "Provide a valid Coinbase order ID.",
            )
        return self.request_json(
            method="GET",
            path_template="/api/v3/brokerage/orders/historical/{order_id}",
            concrete_path=f"/api/v3/brokerage/orders/historical/{order_id}",
        )

    def get_fills_page(
        self,
        *,
        limit: int = 100,
        cursor: str | None = None,
        order_ids: list[str] | None = None,
        product_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        params: list[tuple[str, str]] = [("limit", str(limit))]
        if cursor:
            params.append(("cursor", cursor))
        for oid in order_ids or ():
            if not ORDER_ID_RE.fullmatch(oid):
                raise AppError("INVALID_ORDER_ID", "Order ID contains unsupported characters.", "Provide a valid Coinbase order ID.")
            params.append(("order_ids", oid))
        for pid in product_ids or ():
            params.append(("product_ids", pid))
        return self.request_json(
            method="GET",
            path_template="/api/v3/brokerage/orders/historical/fills",
            concrete_path="/api/v3/brokerage/orders/historical/fills",
            query=params,
        )

    def preview_order(self, body: dict[str, Any]) -> dict[str, Any]:
        # Live Gate A verified POST /orders/preview succeeds on view-only CDP keys
        # and accepts requests omitting OpenAPI's stray required commission_rate field.
        clean_body = {k: v for k, v in body.items() if k != "commission_rate"}
        return self.request_json(
            method="POST",
            path_template="/api/v3/brokerage/orders/preview",
            concrete_path="/api/v3/brokerage/orders/preview",
            json_body=clean_body,
        )
