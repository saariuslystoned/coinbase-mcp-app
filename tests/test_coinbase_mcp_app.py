"""Pure-stdlib unit & stdio subprocess tests for coinbase-mcp-app (zero live network calls)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "bin" / "coinbase-mcp-app"

from coinbase_mcp_app.jwt_auth import (  # noqa: E402
    build_cdp_es256_jwt,
    encode_sec1_p256_pem,
    public_point_from_secret,
    verify_es256_jwt,
)
from coinbase_mcp_app.server import (  # noqa: E402
    CoinbaseMcpApp,
    ConfirmationTokenCodec,
    UI_MIME_TYPE,
    UI_RESOURCE_URI,
    build_resource_definitions,
    build_tool_definitions,
)

TEST_SCALAR = 0x1A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F809
FIXED_NOW = datetime(2026, 11, 21, 0, 0, 0, tzinfo=timezone.utc)


class CoinbaseMcpAppTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmp_ctx.name)
        self.data_dir = self.tmp / "data"
        self.now_box = [FIXED_NOW]

    def tearDown(self) -> None:
        self.tmp_ctx.cleanup()

    def _demo_app(self, *, max_order_usd: Decimal = Decimal("250")) -> CoinbaseMcpApp:
        return CoinbaseMcpApp(
            data_dir=self.data_dir,
            demo_mode=True,
            max_order_usd=max_order_usd,
            token_codec=ConfirmationTokenCodec(b"unit-test-hmac-secret-32-bytes!!"),
            now_fn=lambda: self.now_box[0],
        )

    def test_pure_stdlib_es256_jwt_roundtrip(self) -> None:
        tok = build_cdp_es256_jwt(
            key_name="organizations/demo/apiKeys/key1",
            private_scalar=TEST_SCALAR,
            method="GET",
            request_path="/api/v3/brokerage/key_permissions",
            now=1795219200,
        )
        hdr, payload = verify_es256_jwt(tok, public_point_from_secret(TEST_SCALAR))
        self.assertEqual(hdr["alg"], "ES256")
        self.assertEqual(payload["iss"], "cdp")
        self.assertEqual(payload["uri"], "GET api.coinbase.com/api/v3/brokerage/key_permissions")
        self.assertIn("BEGIN EC PRIVATE KEY", encode_sec1_p256_pem(TEST_SCALAR))

    def test_cross_host_sep1865_metadata_and_zero_network_bundle(self) -> None:
        tools = {t["name"]: t for t in build_tool_definitions()}
        self.assertEqual(len(tools), 9)
        for name, tool in tools.items():
            meta = tool["_meta"]
            self.assertEqual(meta["ui"]["resourceUri"], UI_RESOURCE_URI, name)
            self.assertEqual(meta["ui/resourceUri"], UI_RESOURCE_URI, name)
            self.assertEqual(meta["openai/outputTemplate"], UI_RESOURCE_URI, name)
        for app_only in ("coinbase_order_preview_refresh", "coinbase_order_execute", "coinbase_order_reject", "coinbase_order_cancel"):
            self.assertEqual(tools[app_only]["_meta"]["ui"]["visibility"], ["app"])
            self.assertTrue(tools[app_only]["_meta"]["openai/widgetAccessible"])
            self.assertFalse(tools[app_only]["inputSchema"]["additionalProperties"])

        self.assertIn("com.google.antigravity/ui", tools["coinbase_balance"]["_meta"])
        self.assertNotIn("com.google.antigravity/ui", tools["coinbase_order_preview"]["_meta"])

        res = build_resource_definitions()[0]
        self.assertEqual(res["mimeType"], UI_MIME_TYPE)
        self.assertEqual(res["_meta"]["ui"]["csp"], {"connectDomains": [], "resourceDomains": []})

        app = self._demo_app()
        read_resp = app.handle_jsonrpc({"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": {"uri": UI_RESOURCE_URI}})
        assert read_resp is not None
        html = read_resp["result"]["contents"][0]["text"]
        self.assertNotRegex(html, r'(?:src|href)\s*=\s*["\']https?:')
        self.assertNotIn("window.openai", html)
        self.assertNotIn("/Users/", html)

    def test_demo_mode_balance_preview_refresh_execute_and_guards(self) -> None:
        app = self._demo_app(max_order_usd=Decimal("100"))

        bal = app.call_tool("coinbase_balance", {})
        self.assertFalse(bal["isError"])
        bal_sc = bal["structuredContent"]
        self.assertTrue(bal_sc["demo_mode"])
        self.assertEqual(bal_sc["balances"]["usd_fiat"][0]["available_balance"], "250")
        self.assertEqual([s["currency"] for s in bal_sc["balances"]["stablecoins"]], ["USDC"])
        self.assertEqual(bal_sc["hidden_zero_count"], 1)
        crypto_rows = bal_sc["balances"]["crypto"]
        self.assertEqual([c["currency"] for c in crypto_rows], ["BTC", "ETH"])
        self.assertEqual(crypto_rows[0]["advisory_usd"], "2375")
        self.assertEqual(crypto_rows[0]["allocation_pct"], "67.4")
        self.assertEqual(crypto_rows[0]["unrealized_pnl_usd"], "320.5")
        self.assertEqual(bal_sc["advisory_breakdown"]["total_unrealized_pnl_usd"], "275.25")
        self.assertEqual(len(bal_sc["open_orders"]), 1)
        self.assertEqual(bal_sc["open_orders"][0]["order_id"], "demo-open-order-001")

        prev = app.call_tool("coinbase_quote_preview", {"product_id": "BTC-USDC", "side": "BUY", "quote_size": "10.00"})
        self.assertFalse(prev["isError"])
        tok1 = prev["_meta"]["coinbaseApp/confirmationToken"]
        self.assertNotIn(tok1, json.dumps(prev["content"]))
        self.assertNotIn(tok1, json.dumps(prev["structuredContent"]))

        refreshed = app.call_tool("coinbase_order_preview_refresh", {"confirmation_token": tok1})
        self.assertFalse(refreshed["isError"])
        tok2 = refreshed["_meta"]["coinbaseApp/confirmationToken"]
        self.assertNotEqual(tok1, tok2)

        # Stale token rejected
        self.assertEqual(app.call_tool("coinbase_order_execute", {"confirmation_token": tok1})["structuredContent"]["error_code"], "CONFIRMATION_TOKEN_MISMATCH")
        # Raw trade args rejected
        self.assertEqual(app.call_tool("coinbase_order_execute", {"confirmation_token": tok2, "product_id": "ETH-USD"})["structuredContent"]["error_code"], "INVALID_USAGE")

        approved = app.call_tool("coinbase_order_execute", {"confirmation_token": tok2})
        self.assertFalse(approved["isError"])
        self.assertEqual(approved["structuredContent"]["phase"], "approved_dry_run")
        self.assertFalse(approved["structuredContent"]["receipt"]["live_order_submitted"])

        # Direct replay blocked; check_status=True idempotent
        self.assertEqual(app.call_tool("coinbase_order_execute", {"confirmation_token": tok2})["structuredContent"]["error_code"], "CONFIRMATION_TOKEN_REPLAYED")
        idem = app.call_tool("coinbase_order_execute", {"confirmation_token": tok2, "check_status": True})
        self.assertFalse(idem["isError"])
        self.assertTrue(idem["structuredContent"]["idempotent_replay"])

        # Cap & expiry checks
        over = app.call_tool("coinbase_quote_preview", {"product_id": "BTC-USDC", "side": "BUY", "quote_size": "200.00"})
        self.assertEqual(app.call_tool("coinbase_order_execute", {"confirmation_token": over["_meta"]["coinbaseApp/confirmationToken"]})["structuredContent"]["error_code"], "ORDER_CAP_EXCEEDED")

        exp_prev = app.call_tool("coinbase_quote_preview", {"product_id": "BTC-USDC", "side": "BUY", "quote_size": "10.00", "ttl_seconds": 30})
        self.now_box[0] = FIXED_NOW + timedelta(seconds=35)
        self.assertEqual(app.call_tool("coinbase_order_execute", {"confirmation_token": exp_prev["_meta"]["coinbaseApp/confirmationToken"]})["structuredContent"]["error_code"], "CONFIRMATION_TOKEN_EXPIRED")

    def test_stdio_launcher_zero_path_demo_handshake(self) -> None:
        reqs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "coinbase_balance", "arguments": {}}},
        ]
        proc = subprocess.run(
            ["bash", str(BIN), "--demo", "--data-dir", str(self.data_dir)],
            input="\n".join(json.dumps(r) for r in reqs) + "\n",
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        out = [json.loads(ln) for ln in proc.stdout.splitlines() if ln.strip()]
        self.assertEqual([r["id"] for r in out], [1, 2, 3])
        self.assertEqual(len(out[1]["result"]["tools"]), 9)
        self.assertFalse(out[2]["result"]["isError"])
        self.assertTrue(out[2]["result"]["structuredContent"]["demo_mode"])


if __name__ == "__main__":
    unittest.main()
