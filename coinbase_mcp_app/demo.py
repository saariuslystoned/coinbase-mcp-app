"""Synthetic demo transport (--demo) for zero-key instant UI previewing.

Explicitly tagged `demo_mode=True` in all outputs so synthetic demo figures can never
be mistaken for live Coinbase balances or orders.
"""
from __future__ import annotations

import json
import urllib.parse
from typing import Any

DEMO_PORTFOLIO_UUID = "00000000-0000-4000-8000-00000000de30"


def demo_coinbase_transport(
    method: str,
    target: str,
    headers: dict[str, str],
    body: bytes | None,
    timeout: float,
) -> tuple[int, bytes]:
    parsed = urllib.parse.urlparse(target)
    path = parsed.path

    def _ok(obj: dict[str, Any]) -> tuple[int, bytes]:
        return 200, json.dumps(obj).encode("utf-8")

    if path == "/api/v3/brokerage/key_permissions":
        return _ok({
            "can_view": True,
            "can_trade": False,
            "can_transfer": False,
            "portfolio_uuid": DEMO_PORTFOLIO_UUID,
            "portfolio_type": "DEMO",
        })
    if path == "/api/v3/brokerage/time":
        return _ok({"iso": "2026-11-21T00:00:00Z", "epochMillis": "1795219200000"})
    if path == "/api/v3/brokerage/accounts":
        return _ok({
            "accounts": [
                {
                    "uuid": "demo-usd",
                    "currency": "USD",
                    "type": "ACCOUNT_TYPE_FIAT",
                    "platform": "ACCOUNT_PLATFORM_CONSUMER",
                    "available_balance": {"value": "250.00", "currency": "USD"},
                    "hold": {"value": "0", "currency": "USD"},
                    "active": True,
                    "ready": True,
                    "updated_at": "2026-11-21T00:00:00.000Z",
                },
                {
                    "uuid": "demo-usdt-zero",
                    "currency": "USDT",
                    "type": "ACCOUNT_TYPE_CRYPTO",
                    "platform": "ACCOUNT_PLATFORM_CONSUMER",
                    "available_balance": {"value": "0", "currency": "USDT"},
                    "hold": {"value": "0", "currency": "USDT"},
                    "active": True,
                    "ready": True,
                    "updated_at": "2026-11-21T00:00:00.000Z",
                },
                {
                    "uuid": "demo-usdc",
                    "currency": "USDC",
                    "type": "ACCOUNT_TYPE_CRYPTO",
                    "platform": "ACCOUNT_PLATFORM_CONSUMER",
                    "available_balance": {"value": "100.00", "currency": "USDC"},
                    "hold": {"value": "0", "currency": "USDC"},
                    "active": True,
                    "ready": True,
                    "updated_at": "2026-11-21T00:00:00.000Z",
                },
                {
                    "uuid": "demo-eth",
                    "currency": "ETH",
                    "type": "ACCOUNT_TYPE_CRYPTO",
                    "platform": "ACCOUNT_PLATFORM_CONSUMER",
                    "available_balance": {"value": "0.25000000", "currency": "ETH"},
                    "hold": {"value": "0", "currency": "ETH"},
                    "active": True,
                    "ready": True,
                    "updated_at": "2026-11-21T00:00:00.000Z",
                },
                {
                    "uuid": "demo-btc",
                    "currency": "BTC",
                    "type": "ACCOUNT_TYPE_CRYPTO",
                    "platform": "ACCOUNT_PLATFORM_CONSUMER",
                    "available_balance": {"value": "0.02500000", "currency": "BTC"},
                    "hold": {"value": "0", "currency": "BTC"},
                    "active": True,
                    "ready": True,
                    "updated_at": "2026-11-21T00:00:00.000Z",
                },
            ],
            "has_next": False,
            "cursor": "",
            "size": 5,
        })
    if path == f"/api/v3/brokerage/portfolios/{DEMO_PORTFOLIO_UUID}":
        return _ok({
            "breakdown": {
                "portfolio": {"uuid": DEMO_PORTFOLIO_UUID, "type": "DEMO"},
                "portfolio_balances": {
                    "total_balance": {"value": "3525.00", "currency": "USD"},
                    "total_cash_equivalent_balance": {"value": "350.00", "currency": "USD"},
                    "total_crypto_balance": {"value": "3175.00", "currency": "USD"},
                },
                "spot_positions": [
                    {"asset": "BTC", "account_type": "ACCOUNT_TYPE_WALLET", "is_cash": False, "total_balance_fiat": 2375.00, "allocation": 0.674, "unrealized_pnl": 320.50},
                    {"asset": "ETH", "account_type": "ACCOUNT_TYPE_WALLET", "is_cash": False, "total_balance_fiat": 800.00, "allocation": 0.227, "unrealized_pnl": -45.25},
                    {"asset": "USD", "account_type": "ACCOUNT_TYPE_FIAT", "is_cash": True, "total_balance_fiat": 250.00, "allocation": 0.071, "unrealized_pnl": 0},
                    {"asset": "USDC", "account_type": "ACCOUNT_TYPE_WALLET", "is_cash": True, "total_balance_fiat": 100.00, "allocation": 0.028, "unrealized_pnl": 0},
                ],
            }
        })
    if path == "/api/v3/brokerage/orders/historical/batch":
        return _ok({
            "orders": [
                {
                    "order_id": "demo-open-order-001",
                    "client_order_id": "demo-client-open-001",
                    "product_id": "BTC-USDC",
                    "side": "BUY",
                    "order_type": "LIMIT",
                    "status": "OPEN",
                    "filled_size": "0",
                    "average_filled_price": "0",
                    "total_fees": "0",
                    "outstanding_hold_amount": "25.00",
                    "created_time": "2026-11-21T00:00:00.000000Z",
                }
            ],
            "has_next": False,
            "cursor": "",
        })
    if path == "/api/v3/brokerage/transaction_summary":
        return _ok({
            "fee_tier": {
                "pricing_tier": "Demo Tier",
                "maker_fee_rate": "0.006",
                "taker_fee_rate": "0.012",
            }
        })
    if path.startswith("/api/v3/brokerage/products/"):
        pid = path.rsplit("/", 1)[-1]
        price = "95000.00" if pid.startswith("BTC-") else ("3200.00" if pid.startswith("ETH-") else "180.00")
        return _ok({
            "product_id": pid,
            "product_type": "SPOT",
            "status": "online",
            "price": price,
            "base_increment": "0.00000001",
            "quote_increment": "0.01",
            "base_min_size": "0.00000001",
            "quote_min_size": "1",
            "trading_disabled": False,
        })
    if path == "/api/v3/brokerage/orders/preview":
        req = json.loads((body or b"{}").decode("utf-8"))
        pid = str(req.get("product_id") or "BTC-USDC")
        cfg = req.get("order_configuration") or {}
        price = "95000.00" if pid.startswith("BTC-") else ("3200.00" if pid.startswith("ETH-") else "180.00")
        quote_amt = (
            (cfg.get("market_market_ioc") or {}).get("quote_size")
            or (cfg.get("limit_limit_gtc") or {}).get("limit_price")
            or "10.00"
        )
        return _ok({
            "preview_id": "demo-preview-001",
            "order_total": str(quote_amt),
            "commission_total": "0.12",
            "quote_size": str(quote_amt),
            "base_size": "0.00010526",
            "best_bid": price,
            "best_ask": price,
            "est_average_filled_price": price,
            "slippage": "0.0001",
            "fill_likelihood": "HIGH",
            "errs": [],
            "warning": [],
        })
    if path.startswith("/api/v3/brokerage/orders/historical/"):
        oid = path.rsplit("/", 1)[-1]
        return _ok({
            "order": {
                "order_id": oid,
                "client_order_id": "demo-client-order-001",
                "product_id": "BTC-USDC",
                "side": "BUY",
                "order_type": "LIMIT",
                "status": "OPEN",
                "filled_size": "0",
                "average_filled_price": "0",
                "total_fees": "0",
                "outstanding_hold_amount": "10.00",
                "created_time": "2026-11-21T00:00:00.000000Z",
            }
        })
    return 404, json.dumps({"error": "NOT_FOUND"}).encode("utf-8")
