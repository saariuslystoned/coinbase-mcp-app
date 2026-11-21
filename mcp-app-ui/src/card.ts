import {
  App,
  applyDocumentTheme,
  applyHostStyleVariables,
} from "@modelcontextprotocol/ext-apps";

type JsonMap = Record<string, unknown>;

interface ToolResultPayload {
  content?: Array<{ type?: string; text?: string }>;
  structuredContent?: JsonMap;
  isError?: boolean;
  _meta?: JsonMap;
}

interface CardState {
  loading: boolean;
  loadingLabel: string;
  busyAction: string | null;
  errorMessage: string | null;
  view: string | null;
  data: JsonMap | null;
  confirmationToken: string | null;
  unknownRecovery: boolean;
}

const state: CardState = {
  loading: true,
  loadingLabel: "Connecting to Coinbase MCP App…",
  busyAction: null,
  errorMessage: null,
  view: null,
  data: null,
  confirmationToken: null,
  unknownRecovery: false,
};

let inFlightCalls = 0;
let countdownTimer: number | null = null;
let refreshTimer: number | null = null;
let hostCapabilities: JsonMap = {};

const rootEl = document.getElementById("app") as HTMLDivElement;

const app = new App({ name: "Coinbase Spot Trade Card", version: "0.1.0" }, {});

function clearTimers(): void {
  if (countdownTimer !== null) {
    window.clearInterval(countdownTimer);
    countdownTimer = null;
  }
  if (refreshTimer !== null) {
    window.clearTimeout(refreshTimer);
    refreshTimer = null;
  }
}

function escapeHtml(value: unknown): string {
  const s = value === null || value === undefined ? "" : String(value);
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function asStr(obj: JsonMap | null | undefined, key: string, fallback = "—"): string {
  if (!obj) return fallback;
  const val = obj[key];
  if (val === null || val === undefined || val === "") return fallback;
  return String(val);
}

function asObj(obj: JsonMap | null | undefined, key: string): JsonMap | null {
  if (!obj) return null;
  const val = obj[key];
  return val && typeof val === "object" && !Array.isArray(val) ? (val as JsonMap) : null;
}

function asArr(obj: JsonMap | null | undefined, key: string): unknown[] {
  if (!obj) return [];
  const val = obj[key];
  return Array.isArray(val) ? val : [];
}

function secondsRemaining(expiresAt: string | null): number | null {
  if (!expiresAt) return null;
  const ms = Date.parse(expiresAt) - Date.now();
  if (!Number.isFinite(ms)) return null;
  return Math.max(0, Math.ceil(ms / 1000));
}

function canSendMessage(): boolean {
  return Boolean(hostCapabilities && (hostCapabilities as JsonMap).message);
}

function canUpdateContext(): boolean {
  return Boolean(hostCapabilities && (hostCapabilities as JsonMap).updateModelContext);
}

async function safeUpdateModelContext(summaryText: string): Promise<void> {
  if (!canUpdateContext()) return;
  try {
    await app.updateModelContext({
      content: [{ type: "text", text: summaryText }],
    });
  } catch {
    // Non-fatal on hosts without model context updates (e.g. global view)
  }
}

function applyResult(result: ToolResultPayload | null | undefined): void {
  clearTimers();
  state.loading = false;
  state.busyAction = null;
  state.unknownRecovery = false;

  if (!result) {
    state.errorMessage = "Empty tool response received.";
    render();
    return;
  }

  const meta = result._meta && typeof result._meta === "object" ? result._meta : null;
  if (meta && typeof meta["coinbaseApp/confirmationToken"] === "string") {
    state.confirmationToken = meta["coinbaseApp/confirmationToken"] as string;
  }

  const sc =
    result.structuredContent && typeof result.structuredContent === "object"
      ? (result.structuredContent as JsonMap)
      : null;

  if (result.isError) {
    const errText =
      (sc && typeof sc.error_message === "string" && sc.error_message) ||
      result.content?.find((c) => c.type === "text" && c.text)?.text ||
      "Coinbase MCP tool returned an error.";
    state.errorMessage = errText;
    if (sc && typeof sc.view === "string") {
      state.view = sc.view;
      state.data = sc;
    }
    render();
    return;
  }

  state.errorMessage = null;
  if (sc) {
    state.data = sc;
    state.view = typeof sc.view === "string" ? sc.view : "order_confirm";
    if (
      sc.phase === "approved_dry_run" ||
      sc.phase === "rejected" ||
      sc.phase === "cancel_approved_dry_run" ||
      sc.phase === "cancel_kept"
    ) {
      state.confirmationToken = null;
    }
  } else {
    const fallbackText = result.content?.find((c) => c.type === "text" && c.text)?.text;
    state.errorMessage = fallbackText || "Tool returned no structured content.";
  }

  scheduleQuoteLifecycle();
  render();
}

function scheduleQuoteLifecycle(): void {
  clearTimers();
  if (!state.data) return;
  const view = state.view;
  const phase = asStr(state.data, "phase", "");
  if ((view !== "order_confirm" && view !== "cancel_confirm") || phase !== "preview") {
    return;
  }

  const expiresAt = typeof state.data.expires_at === "string" ? state.data.expires_at : null;
  if (expiresAt) {
    countdownTimer = window.setInterval(() => {
      const rem = secondsRemaining(expiresAt);
      const badge = document.getElementById("ttl-countdown");
      if (badge && rem !== null) {
        badge.textContent = rem > 0 ? `Expires in ${rem}s` : "Expired";
      }
      if (rem !== null && rem <= 0) {
        clearTimers();
        if (state.data) {
          state.data = { ...state.data, phase: "expired" };
        }
        render();
      }
    }, 1000);
  }

  const refreshMs = Number(state.data.refresh_after_ms || 0);
  const refreshTool = typeof state.data.__refresh_tool === "string" ? state.data.__refresh_tool : null;
  if (view === "order_confirm" && refreshTool && state.confirmationToken && refreshMs >= 5000) {
    refreshTimer = window.setTimeout(() => {
      void callAppTool(refreshTool, { confirmation_token: state.confirmationToken }, { silent: true });
    }, refreshMs);
  }
}

async function callAppTool(
  toolName: string,
  args: JsonMap,
  options: { silent?: boolean; actionLabel?: string; isExecute?: boolean } = {}
): Promise<void> {
  if (inFlightCalls >= 2) return;
  inFlightCalls += 1;
  if (!options.silent) {
    state.busyAction = options.actionLabel || toolName;
    state.errorMessage = null;
    render();
  }
  try {
    const res = (await app.callServerTool({
      name: toolName,
      arguments: args,
    })) as ToolResultPayload;
    applyResult(res);
    if (!res.isError && res.structuredContent) {
      const sc = res.structuredContent;
      if (sc.phase === "approved_dry_run") {
        const cid = asStr(sc, "client_order_id", "");
        const pair = asStr(asObj(sc, "order"), "product_id", "");
        const side = asStr(asObj(sc, "order"), "side", "");
        await safeUpdateModelContext(
          `User clicked Approve (Dry Run) for ${side} ${pair} (client_order_id=${cid}, execution_mode=dry_run_preview_only; no live Coinbase order was placed).`
        );
      } else if (sc.phase === "rejected") {
        const cid = asStr(sc, "client_order_id", "");
        await safeUpdateModelContext(`User clicked Reject on Coinbase order draft (client_order_id=${cid}).`);
      } else if (sc.phase === "cancel_approved_dry_run") {
        const oid = asStr(asObj(sc, "order"), "order_id", "");
        await safeUpdateModelContext(
          `User clicked Confirm Cancel (Dry Run) for Coinbase order ${oid} (dry_run_preview_only; no live cancel sent).`
        );
      }
    }
  } catch (err) {
    state.busyAction = null;
    const msg = err instanceof Error ? err.message : String(err);
    if (options.isExecute) {
      state.unknownRecovery = true;
      state.errorMessage = `Execution status unknown (${msg}). Use Check Status before retrying to prevent duplicates.`;
    } else if (!options.silent) {
      state.errorMessage = `Tool call failed: ${msg}`;
    }
    render();
  } finally {
    inFlightCalls = Math.max(0, inFlightCalls - 1);
  }
}

function renderOrderConfirm(data: JsonMap): string {
  const order = asObj(data, "order") || {};
  const preview = asObj(data, "preview") || {};
  const receipt = asObj(data, "receipt");
  const account = asObj(data, "account") || {};
  const phase = asStr(data, "phase", "preview");
  const side = asStr(order, "side", "BUY").toUpperCase();
  const productId = asStr(order, "product_id", "—");
  const orderType = asStr(order, "order_type", "MARKET");
  const tif = asStr(order, "time_in_force", "IOC");
  const amount = asStr(order, "amount", "—");
  const amountCurrency = asStr(order, "amount_currency", "");
  const amountUnit = asStr(order, "amount_unit", "");
  const limitPrice = order.limit_price ? asStr(order, "limit_price") : null;
  const quoteCurrency = asStr(order, "quote_currency", "");
  const errs = asArr(preview, "errs").map(String);
  const warnings = asArr(preview, "warning").map(String);
  const expiresAt = typeof data.expires_at === "string" ? data.expires_at : null;
  const rem = secondsRemaining(expiresAt);
  const expired = phase === "expired" || (phase === "preview" && rem !== null && rem <= 0);
  const intentHash = asStr(data, "intent_sha256", "").slice(0, 12);
  const clientOrderId = asStr(data, "client_order_id", "—");
  const execMode = asStr(data, "execution_mode", "dry_run_preview_only");

  const sideClass = side === "SELL" ? "pill-sell" : "pill-buy";
  const phaseBadge =
    phase === "approved_dry_run"
      ? `<span class="pill pill-ok">DRY-RUN APPROVED</span>`
      : phase === "rejected"
        ? `<span class="pill pill-muted">REJECTED</span>`
        : expired
          ? `<span class="pill pill-warn">EXPIRED</span>`
          : `${data.demo_mode ? `<span class="pill pill-warn">DEMO · SYNTHETIC</span>` : `<span class="pill pill-dry">DRY RUN · VIEW-ONLY</span>`}`;

  const ttlBadge =
    phase === "preview" && rem !== null
      ? `<span id="ttl-countdown" class="mono muted">${rem > 0 ? `Expires in ${rem}s` : "Expired"}</span>`
      : `<span class="mono muted">${escapeHtml(asStr(account, "portfolio_type", "SPOT"))}</span>`;

  const errHtml = errs.length
    ? `<div class="banner banner-danger"><strong>Coinbase preview blocked:</strong> ${escapeHtml(errs.join(", "))}</div>`
    : "";
  const warnHtml = warnings.length
    ? `<div class="banner banner-warn">${escapeHtml(warnings.join(" · "))}</div>`
    : "";
  const localErrHtml = state.errorMessage
    ? `<div class="banner banner-danger">${escapeHtml(state.errorMessage)}</div>`
    : "";

  const receiptHtml =
    phase === "approved_dry_run" && receipt
      ? `<div class="banner banner-ok">
          <strong>Dry-run receipt persisted locally</strong> (no live Coinbase order placed).<br>
          <span class="mono">client_order_id: ${escapeHtml(asStr(receipt, "client_order_id", clientOrderId))}</span><br>
          <span class="muted">Dry-run mode only. Hardware biometric signing (macOS Touch ID / 1Password) is required before live trading.</span>
        </div>`
      : phase === "rejected"
        ? `<div class="banner banner-muted">Order draft rejected and recorded locally. No order placed.</div>`
        : "";

  const confirmDisabled =
    Boolean(state.busyAction) || expired || errs.length > 0 || !state.confirmationToken;
  const confirmTool = asStr(data, "__confirm_tool", "coinbase_order_execute");
  const rejectTool = asStr(data, "__reject_tool", "coinbase_order_reject");
  const refreshTool = asStr(data, "__refresh_tool", "coinbase_order_preview_refresh");

  let actionsHtml = "";
  if (state.unknownRecovery && state.confirmationToken) {
    actionsHtml = `
      <div class="actions">
        <button class="btn btn-primary" data-action="check-status" data-tool="${escapeHtml(confirmTool)}" ${state.busyAction ? "disabled" : ""}>
          Check Status (Idempotent)
        </button>
      </div>`;
  } else if (phase === "preview" && !expired) {
    actionsHtml = `
      <div class="actions">
        <button class="btn btn-primary" data-action="confirm-order" data-tool="${escapeHtml(confirmTool)}" ${confirmDisabled ? "disabled" : ""}>
          ${state.busyAction === "approving" ? "Recording Dry Run…" : "Approve Trade (Dry Run)"}
        </button>
        <button class="btn btn-secondary" data-action="reject-order" data-tool="${escapeHtml(rejectTool)}" ${state.busyAction || !state.confirmationToken ? "disabled" : ""}>
          Reject
        </button>
        <button class="btn btn-ghost" data-action="refresh-quote" data-tool="${escapeHtml(refreshTool)}" ${state.busyAction || !state.confirmationToken ? "disabled" : ""}>
          Refresh
        </button>
      </div>`;
  } else if (expired) {
    actionsHtml = `
      <div class="actions">
        ${
          canSendMessage()
            ? `<button class="btn btn-primary" data-action="request-new-quote">Ask for Fresh Quote</button>`
            : `<span class="muted">Quote expired — request a fresh preview in chat.</span>`
        }
      </div>`;
  }

  return `
    <div class="card">
      <div class="header">
        <div class="title-row">
          <span class="pill ${sideClass}">${escapeHtml(side)}</span>
          <span class="pair">${escapeHtml(productId)}</span>
          ${phaseBadge}
        </div>
        ${ttlBadge}
      </div>

      ${localErrHtml}${errHtml}${warnHtml}${receiptHtml}

      <div class="grid">
        <div class="kv"><span class="k">Order</span><span class="v">${escapeHtml(orderType)} · ${escapeHtml(tif)}${order.post_only ? " · POST-ONLY" : ""}</span></div>
        <div class="kv"><span class="k">Size (${escapeHtml(amountUnit)})</span><span class="v mono">${escapeHtml(amount)} ${escapeHtml(amountCurrency)}</span></div>
        ${limitPrice ? `<div class="kv"><span class="k">Limit Price</span><span class="v mono">${escapeHtml(limitPrice)} ${escapeHtml(quoteCurrency)}</span></div>` : ""}
        <div class="kv"><span class="k">Est. Avg Price</span><span class="v mono">${escapeHtml(asStr(preview, "est_average_filled_price"))} ${escapeHtml(quoteCurrency)}</span></div>
        <div class="kv"><span class="k">Est. Total</span><span class="v mono">${escapeHtml(asStr(preview, "order_total"))} ${escapeHtml(quoteCurrency)}</span></div>
        <div class="kv"><span class="k">Est. Commission</span><span class="v mono">${escapeHtml(asStr(preview, "commission_total"))} ${escapeHtml(quoteCurrency)}</span></div>
        <div class="kv"><span class="k">Slippage / Fill</span><span class="v mono">${escapeHtml(asStr(preview, "slippage", "0"))} · ${escapeHtml(asStr(preview, "fill_likelihood", "—"))}</span></div>
        <div class="kv"><span class="k">Bid / Ask</span><span class="v mono">${escapeHtml(asStr(preview, "best_bid"))} / ${escapeHtml(asStr(preview, "best_ask"))}</span></div>
      </div>

      <div class="meta-bar mono">
        <span>hash:${escapeHtml(intentHash || "—")}</span>
        <span>mode:${escapeHtml(execMode)}</span>
        <span>quote:${escapeHtml(quoteCurrency)} (distinct from USD/USDC)</span>
      </div>

      ${actionsHtml}
    </div>
  `;
}

function renderCancelConfirm(data: JsonMap): string {
  const order = asObj(data, "order") || {};
  const receipt = asObj(data, "receipt");
  const phase = asStr(data, "phase", "preview");
  const cancelTool = asStr(data, "__confirm_tool", "coinbase_order_cancel");
  const rejectTool = asStr(data, "__reject_tool", "coinbase_order_reject");
  const localErrHtml = state.errorMessage
    ? `<div class="banner banner-danger">${escapeHtml(state.errorMessage)}</div>`
    : "";
  const receiptHtml =
    phase === "cancel_approved_dry_run" && receipt
      ? `<div class="banner banner-ok"><strong>Dry-run cancel receipt saved</strong> (no live Coinbase cancel sent).</div>`
      : phase === "rejected"
        ? `<div class="banner banner-muted">Cancel dismissed — order left untouched.</div>`
        : "";

  const actionsHtml =
    phase === "preview"
      ? `<div class="actions">
          <button class="btn btn-danger" data-action="confirm-cancel" data-tool="${escapeHtml(cancelTool)}" ${state.busyAction || !state.confirmationToken ? "disabled" : ""}>
            Confirm Cancel (Dry Run)
          </button>
          <button class="btn btn-secondary" data-action="reject-order" data-tool="${escapeHtml(rejectTool)}" ${state.busyAction || !state.confirmationToken ? "disabled" : ""}>
            Keep Order
          </button>
        </div>`
      : "";

  return `
    <div class="card">
      <div class="header">
        <div class="title-row">
          <span class="pill pill-sell">CANCEL</span>
          <span class="pair">${escapeHtml(asStr(order, "product_id", "—"))}</span>
          ${data.demo_mode ? `<span class="pill pill-warn">DEMO · SYNTHETIC</span>` : `<span class="pill pill-dry">DRY RUN · VIEW-ONLY</span>`}
        </div>
        <span class="mono muted">${escapeHtml(asStr(order, "provider_status", "UNKNOWN"))}</span>
      </div>
      ${localErrHtml}${receiptHtml}
      <div class="grid">
        <div class="kv"><span class="k">Order ID</span><span class="v mono">${escapeHtml(asStr(order, "order_id"))}</span></div>
        <div class="kv"><span class="k">Side / Type</span><span class="v">${escapeHtml(asStr(order, "side"))} · ${escapeHtml(asStr(order, "order_type"))}</span></div>
        <div class="kv"><span class="k">Filled Size</span><span class="v mono">${escapeHtml(asStr(order, "filled_size", "0"))}</span></div>
        <div class="kv"><span class="k">Outstanding Hold</span><span class="v mono">${escapeHtml(asStr(order, "outstanding_hold_amount", "0"))}</span></div>
      </div>
      ${actionsHtml}
    </div>
  `;
}

function renderOrderStatus(data: JsonMap): string {
  const order = asObj(data, "order");
  const receipt = asObj(data, "receipt");
  const source = asStr(data, "lookup_source", "local_receipt");
  const statusTool = asStr(data, "__status_tool", "coinbase_order_status");
  const refreshId = order ? asStr(order, "order_id", "") : receipt ? asStr(receipt, "intent_id", "") : "";
  const refreshKey = order ? "order_id" : "intent_id";

  const rows = order
    ? `
      <div class="kv"><span class="k">Order ID</span><span class="v mono">${escapeHtml(asStr(order, "order_id"))}</span></div>
      <div class="kv"><span class="k">Pair / Side</span><span class="v">${escapeHtml(asStr(order, "product_id"))} · ${escapeHtml(asStr(order, "side"))}</span></div>
      <div class="kv"><span class="k">Status</span><span class="v mono">${escapeHtml(asStr(order, "provider_status"))} (${escapeHtml(asStr(order, "status"))})</span></div>
      <div class="kv"><span class="k">Filled / Avg Price</span><span class="v mono">${escapeHtml(asStr(order, "filled_size", "0"))} @ ${escapeHtml(asStr(order, "average_filled_price", "—"))}</span></div>
      <div class="kv"><span class="k">Fees / Hold</span><span class="v mono">${escapeHtml(asStr(order, "total_fees", "0"))} / ${escapeHtml(asStr(order, "outstanding_hold_amount", "0"))}</span></div>
      <div class="kv"><span class="k">Created</span><span class="v mono">${escapeHtml(asStr(order, "created_time"))}</span></div>
    `
    : receipt
      ? `
      <div class="kv"><span class="k">Intent ID</span><span class="v mono">${escapeHtml(asStr(receipt, "intent_id"))}</span></div>
      <div class="kv"><span class="k">Client Order ID</span><span class="v mono">${escapeHtml(asStr(receipt, "client_order_id"))}</span></div>
      <div class="kv"><span class="k">State</span><span class="v mono">${escapeHtml(asStr(receipt, "state"))}</span></div>
      <div class="kv"><span class="k">Execution Mode</span><span class="v mono">${escapeHtml(asStr(receipt, "execution_mode"))}</span></div>
      <div class="kv"><span class="k">Updated</span><span class="v mono">${escapeHtml(asStr(receipt, "updated_at"))}</span></div>
    `
      : `<div class="banner banner-muted">No matching order or receipt found.</div>`;

  return `
    <div class="card">
      <div class="header">
        <div class="title-row">
          <span class="pill pill-buy">STATUS</span>
          <span class="pair">${escapeHtml(source === "coinbase_live" ? "Coinbase Order" : "Local Draft / Receipt")}</span>
        </div>
        <button class="btn btn-ghost" data-action="refresh-status" data-tool="${escapeHtml(statusTool)}" data-key="${escapeHtml(refreshKey)}" data-val="${escapeHtml(refreshId)}" ${state.busyAction || !refreshId ? "disabled" : ""}>
          Refresh
        </button>
      </div>
      ${state.errorMessage ? `<div class="banner banner-danger">${escapeHtml(state.errorMessage)}</div>` : ""}
      <div class="grid">${rows}</div>
    </div>
  `;
}

function fmtUsd(raw: unknown, { signed = false }: { signed?: boolean } = {}): string {
  if (raw === null || raw === undefined || raw === "") return "—";
  const num = Number(raw);
  if (!Number.isFinite(num)) return String(raw);
  const abs = Math.abs(num).toLocaleString("en-US", {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  });
  if (num < 0) return `-$${abs}`;
  if (signed && num > 0) return `+$${abs}`;
  return `$${abs}`;
}

function fmtPct(raw: unknown): string {
  if (raw === null || raw === undefined || raw === "") return "";
  const num = Number(raw);
  if (!Number.isFinite(num)) return "";
  return `${num.toFixed(1)}%`;
}

function pnlClass(raw: unknown): string {
  const num = Number(raw);
  if (!Number.isFinite(num) || num === 0) return "muted";
  return num > 0 ? "pnl-pos" : "pnl-neg";
}

function renderBalanceRows(items: unknown[], emptyLabel: string): string {
  if (!items.length) return `<div class="muted small">${escapeHtml(emptyLabel)}</div>`;
  return items
    .map((raw) => {
      const it = raw as JsonMap;
      const cur = asStr(it, "currency");
      const avail = asStr(it, "available_balance", "0");
      const hold = asStr(it, "hold", "0");
      const hasHold = Number(hold) > 0;
      const alloc = fmtPct(it.allocation_pct);
      const hasUsd = it.advisory_usd !== null && it.advisory_usd !== undefined && it.advisory_usd !== "";
      const hasPnl = it.unrealized_pnl_usd !== null && it.unrealized_pnl_usd !== undefined && it.unrealized_pnl_usd !== "";
      return `<div class="holding-row">
        <div class="holding-left">
          <div class="holding-head">
            <span class="mono bold">${escapeHtml(cur)}</span>
            ${alloc ? `<span class="alloc-chip mono">${escapeHtml(alloc)}</span>` : ""}
            ${hasHold ? `<span class="hold-chip mono">hold ${escapeHtml(hold)}</span>` : ""}
          </div>
          <div class="mono muted small">${escapeHtml(avail)} ${escapeHtml(cur)}</div>
        </div>
        <div class="holding-right">
          ${hasUsd ? `<div class="mono bold">${escapeHtml(fmtUsd(it.advisory_usd))}</div>` : `<div class="mono muted">—</div>`}
          ${hasPnl ? `<div class="mono small ${pnlClass(it.unrealized_pnl_usd)}">${escapeHtml(fmtUsd(it.unrealized_pnl_usd, { signed: true }))}</div>` : ""}
        </div>
      </div>`;
    })
    .join("");
}

function renderOpenOrders(items: unknown[]): string {
  if (!items.length) return `<div class="muted small">No open spot orders.</div>`;
  return items
    .map((raw) => {
      const o = raw as JsonMap;
      const side = asStr(o, "side", "").toUpperCase();
      const sideClass = side === "SELL" ? "pill-sell" : "pill-buy";
      return `<div class="bal-row">
        <span class="mono"><span class="pill ${sideClass}">${escapeHtml(side)}</span> ${escapeHtml(asStr(o, "product_id"))} · ${escapeHtml(asStr(o, "order_type"))}</span>
        <span class="mono muted">${escapeHtml(asStr(o, "provider_status"))} · hold ${escapeHtml(asStr(o, "outstanding_hold_amount", "0"))}</span>
      </div>`;
    })
    .join("");
}

function renderBalanceDashboard(data: JsonMap): string {
  const account = asObj(data, "account") || {};
  const balances = asObj(data, "balances") || {};
  const advisory = asObj(data, "advisory_breakdown");
  const feeTier = asObj(data, "fee_tier");
  const receipts = asArr(data, "recent_receipts");
  const openOrders = asArr(data, "open_orders");
  const cryptoItems = asArr(balances, "crypto");
  const hiddenZeros = Number(data.hidden_zero_count || 0);

  const receiptLines = receipts.length
    ? receipts
        .slice(0, 6)
        .map((raw) => {
          const r = raw as JsonMap;
          return `<div class="bal-row">
            <span class="mono">${escapeHtml(asStr(r, "state"))}</span>
            <span class="mono muted">${escapeHtml(asStr(r, "summary", asStr(r, "intent_id").slice(0, 8)))}</span>
          </div>`;
        })
        .join("")
    : `<div class="muted small">No local dry-run receipts yet.</div>`;

  const totalPnlRaw = advisory ? advisory.total_unrealized_pnl_usd : null;
  const hasTotalPnl = totalPnlRaw !== null && totalPnlRaw !== undefined && totalPnlRaw !== "";

  return `
    <div class="card">
      <div class="header">
        <div class="title-row">
          <span class="pill pill-buy">COINBASE SPOT</span>
          <span class="pair">${escapeHtml(asStr(account, "alias", "coinbase"))}</span>
          ${data.demo_mode ? `<span class="pill pill-warn">DEMO · SYNTHETIC</span>` : `<span class="pill pill-dry">VIEW-ONLY · DRY RUN</span>`}
        </div>
        <button class="btn btn-ghost" data-action="refresh-balance" ${state.busyAction ? "disabled" : ""}>
          ${state.busyAction === "refreshing" ? "Refreshing…" : "Refresh"}
        </button>
      </div>

      ${state.errorMessage ? `<div class="banner banner-danger">${escapeHtml(state.errorMessage)}</div>` : ""}

      ${
        advisory
          ? `<div class="summary-strip">
              <div><span class="k">Advisory Total (USD)</span><div class="big mono">${escapeHtml(fmtUsd(advisory.total_balance_usd))}</div></div>
              <div><span class="k">Crypto (USD)</span><div class="mono bold">${escapeHtml(fmtUsd(advisory.total_crypto_balance_usd))}</div></div>
              <div><span class="k">Cash Equiv (USD+USDC)</span><div class="mono bold">${escapeHtml(fmtUsd(advisory.total_cash_equivalent_balance_usd))}</div></div>
              ${hasTotalPnl ? `<div><span class="k">Unrealized P&amp;L</span><div class="mono bold ${pnlClass(totalPnlRaw)}">${escapeHtml(fmtUsd(totalPnlRaw, { signed: true }))}</div></div>` : ""}
            </div>`
          : ""
      }

      <div class="section">
        <div class="sec-title">Spot Crypto (${cryptoItems.length} funded · sorted by USD value)</div>
        ${renderBalanceRows(cryptoItems, "No funded spot crypto")}
      </div>
      <div class="section">
        <div class="sec-title">USD Fiat Cash</div>
        ${renderBalanceRows(asArr(balances, "usd_fiat"), "No USD fiat account")}
      </div>
      <div class="section">
        <div class="sec-title">Stablecoins (separate from USD fiat)</div>
        ${renderBalanceRows(asArr(balances, "stablecoins"), "No funded stablecoins")}
      </div>
      <div class="section">
        <div class="sec-title">Open Spot Orders (${openOrders.length})</div>
        ${renderOpenOrders(openOrders)}
      </div>
      <div class="section">
        <div class="sec-title">Recent MCP App Dry-Run Receipts</div>
        ${receiptLines}
      </div>

      <div class="meta-bar mono">
        ${feeTier ? `<span>tier:${escapeHtml(asStr(feeTier, "pricing_tier"))}</span><span>maker:${escapeHtml(asStr(feeTier, "maker_fee_rate"))}</span><span>taker:${escapeHtml(asStr(feeTier, "taker_fee_rate"))}</span>` : ""}
        ${hiddenZeros > 0 ? `<span>${hiddenZeros} zero-balance wallet${hiddenZeros === 1 ? "" : "s"} hidden</span>` : ""}
      </div>
    </div>
  `;
}

function render(): void {
  if (state.loading) {
    rootEl.innerHTML = `<div class="card"><div class="muted">${escapeHtml(state.loadingLabel)}</div></div>`;
    return;
  }
  if (!state.data) {
    rootEl.innerHTML = `<div class="card">
      <div class="banner banner-danger">${escapeHtml(state.errorMessage || "No Coinbase payload loaded yet.")}</div>
    </div>`;
    return;
  }
  if (state.view === "cancel_confirm") {
    rootEl.innerHTML = renderCancelConfirm(state.data);
  } else if (state.view === "order_status") {
    rootEl.innerHTML = renderOrderStatus(state.data);
  } else if (state.view === "balance_dashboard") {
    rootEl.innerHTML = renderBalanceDashboard(state.data);
  } else {
    rootEl.innerHTML = renderOrderConfirm(state.data);
  }
}

rootEl.addEventListener("click", (ev) => {
  const target = (ev.target as HTMLElement | null)?.closest("button[data-action]") as HTMLButtonElement | null;
  if (!target || target.disabled) return;
  const action = target.dataset.action;
  const tool = target.dataset.tool || "";

  if (action === "confirm-order" && state.confirmationToken) {
    void callAppTool(tool, { confirmation_token: state.confirmationToken }, { actionLabel: "approving", isExecute: true });
  } else if (action === "check-status" && state.confirmationToken) {
    void callAppTool(tool, { confirmation_token: state.confirmationToken, check_status: true }, { actionLabel: "checking" });
  } else if (action === "reject-order" && state.confirmationToken) {
    void callAppTool(tool, { confirmation_token: state.confirmationToken }, { actionLabel: "rejecting" });
  } else if (action === "refresh-quote" && state.confirmationToken) {
    void callAppTool(tool, { confirmation_token: state.confirmationToken }, { actionLabel: "refreshing" });
  } else if (action === "confirm-cancel" && state.confirmationToken) {
    void callAppTool(tool, { confirmation_token: state.confirmationToken }, { actionLabel: "cancelling", isExecute: true });
  } else if (action === "refresh-status") {
    const k = target.dataset.key || "order_id";
    const v = target.dataset.val || "";
    if (v) void callAppTool(tool, { [k]: v }, { actionLabel: "refreshing" });
  } else if (action === "refresh-balance") {
    void callAppTool(asStr(state.data, "__refresh_balance_tool", "coinbase_balance"), {}, { actionLabel: "refreshing" });
  } else if (action === "request-new-quote" && canSendMessage() && state.data) {
    const ord = asObj(state.data, "order") || {};
    const side = asStr(ord, "side", "BUY");
    const pair = asStr(ord, "product_id", "BTC-USD");
    const amt = asStr(ord, "amount", "");
    const ccy = asStr(ord, "amount_currency", "");
    void app.sendMessage({
      role: "user",
      content: [{ type: "text", text: `Please refresh the preview quote for ${side} ${amt} ${ccy} on ${pair}.` }],
    });
  }
});

// Register all SEP-1865 handlers BEFORE calling app.connect()
app.ontoolinput = ({ arguments: args }) => {
  state.loading = true;
  const pair = args && typeof args === "object" && "product_id" in args ? String((args as JsonMap).product_id) : "";
  state.loadingLabel = pair ? `Previewing ${pair} on Coinbase (view-only)…` : "Loading Coinbase Spot data…";
  render();
};

app.ontoolresult = (result) => {
  applyResult(result as unknown as ToolResultPayload);
};

app.ontoolcancelled = () => {
  clearTimers();
  state.loading = false;
  state.busyAction = null;
  state.errorMessage = "Tool call was cancelled by host.";
  render();
};

app.onhostcontextchanged = (ctx) => {
  if (ctx?.theme) applyDocumentTheme(ctx.theme);
  if (ctx?.styles?.variables) applyHostStyleVariables(ctx.styles.variables);
};

async function init(): Promise<void> {
  render();
  try {
    await app.connect();
    const caps = app.getHostCapabilities();
    hostCapabilities = caps && typeof caps === "object" ? (caps as unknown as JsonMap) : {};
    const ctx = app.getHostContext();
    if (ctx?.theme) applyDocumentTheme(ctx.theme);
    if (ctx?.styles?.variables) applyHostStyleVariables(ctx.styles.variables);
  } catch (err) {
    state.loading = false;
    state.errorMessage = `Host bridge connection failed: ${err instanceof Error ? err.message : String(err)}`;
    render();
  }
}

void init();
