import * as esbuild from "esbuild";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const outDir = path.resolve(here, "../coinbase_mcp_app/ui");
const outFile = path.join(outDir, "trade-card.html");

const built = await esbuild.build({
  entryPoints: [path.join(here, "src/card.ts")],
  bundle: true,
  minify: true,
  format: "iife",
  target: ["es2022"],
  write: false,
});

const jsBundle = built.outputFiles[0].text.replaceAll("</script>", "<\\/script>");

const css = `
:root {
  color-scheme: light dark;
}
* { box-sizing: border-box; }
html, body {
  margin: 0;
  padding: 0;
  background: var(--color-background-primary, #ffffff);
  color: var(--color-text-primary, #111827);
  font-family: var(--font-sans, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif);
  font-size: 13px;
  line-height: 1.45;
}
@media (prefers-color-scheme: dark) {
  html, body {
    background: var(--color-background-primary, #11161d);
    color: var(--color-text-primary, #f3f4f6);
  }
}
.card {
  padding: 14px 16px;
  display: flex;
  flex-direction: column;
  gap: 10px;
  max-width: 100%;
}
.header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  flex-wrap: wrap;
}
.title-row {
  display: flex;
  align-items: center;
  gap: 7px;
  flex-wrap: wrap;
}
.pair {
  font-weight: 700;
  font-size: 15px;
  letter-spacing: -0.01em;
}
.pill {
  display: inline-block;
  padding: 2px 7px;
  border-radius: 999px;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.03em;
}
.pill-buy { background: rgba(16, 185, 129, 0.16); color: var(--color-text-success, #059669); }
.pill-sell { background: rgba(239, 68, 68, 0.16); color: var(--color-text-danger, #dc2626); }
.pill-dry { background: rgba(245, 158, 11, 0.16); color: var(--color-text-warning, #b45309); }
.pill-ok { background: rgba(16, 185, 129, 0.2); color: var(--color-text-success, #059669); }
.pill-warn { background: rgba(245, 158, 11, 0.2); color: var(--color-text-warning, #b45309); }
.pill-muted { background: var(--color-background-secondary, rgba(128,128,128,0.14)); color: var(--color-text-secondary, #6b7280); }
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(175px, 1fr));
  gap: 6px 12px;
  padding: 10px 12px;
  border-radius: 8px;
  background: var(--color-background-secondary, rgba(128,128,128,0.08));
  border: 1px solid var(--color-border-secondary, rgba(128,128,128,0.2));
}
.kv { display: flex; flex-direction: column; gap: 1px; }
.k { font-size: 11px; color: var(--color-text-secondary, #6b7280); }
.v { font-weight: 600; word-break: break-word; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; }
.bold { font-weight: 700; }
.small { font-size: 12px; }
.muted { color: var(--color-text-secondary, #6b7280); }
.banner {
  padding: 8px 10px;
  border-radius: 7px;
  font-size: 12px;
  border: 1px solid transparent;
}
.banner-danger { background: rgba(239, 68, 68, 0.12); border-color: rgba(239, 68, 68, 0.3); color: var(--color-text-danger, #dc2626); }
.banner-warn { background: rgba(245, 158, 11, 0.12); border-color: rgba(245, 158, 11, 0.3); color: var(--color-text-warning, #b45309); }
.banner-ok { background: rgba(16, 185, 129, 0.12); border-color: rgba(16, 185, 129, 0.3); color: var(--color-text-success, #059669); }
.banner-muted { background: var(--color-background-secondary, rgba(128,128,128,0.1)); color: var(--color-text-secondary, #6b7280); }
.meta-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 14px;
  font-size: 11px;
  color: var(--color-text-secondary, #6b7280);
}
.actions {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.btn {
  border-radius: 7px;
  padding: 7px 13px;
  font-size: 12.5px;
  font-weight: 600;
  cursor: pointer;
  border: 1px solid transparent;
}
.btn:disabled { opacity: 0.45; cursor: not-allowed; }
.btn-primary {
  background: var(--color-background-info, #0f766e);
  color: #ffffff;
}
.btn-danger {
  background: var(--color-background-danger, #dc2626);
  color: #ffffff;
}
.btn-secondary {
  background: var(--color-background-secondary, rgba(128,128,128,0.15));
  color: var(--color-text-primary, inherit);
  border-color: var(--color-border-secondary, rgba(128,128,128,0.3));
}
.btn-ghost {
  background: transparent;
  color: var(--color-text-secondary, #6b7280);
  border-color: var(--color-border-secondary, rgba(128,128,128,0.28));
}
.summary-strip {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 8px;
  padding: 10px 12px;
  border-radius: 8px;
  background: var(--color-background-secondary, rgba(128,128,128,0.08));
}
.big { font-size: 16px; font-weight: 700; }
.section { display: flex; flex-direction: column; gap: 4px; }
.sec-title { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; color: var(--color-text-secondary, #6b7280); }
.bal-row {
  display: flex;
  justify-content: space-between;
  gap: 10px;
  padding: 4px 8px;
  border-radius: 6px;
  background: var(--color-background-secondary, rgba(128,128,128,0.06));
}
`.trim();

const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Coinbase Spot Trade Card</title>
<style>${css}</style>
</head>
<body>
<div id="app"></div>
<script>${jsBundle}</script>
</body>
</html>
`;

// Zero-network guard: verify no external resource/script/fetch URLs were bundled
if (/(?:src|href)\s*=\s*["']https?:/i.test(html) || /\burl\(\s*['"]?https?:/i.test(html)) {
  throw new Error("External http(s) resource URL detected in trade-card.html; bundle must be zero-network");
}

fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(outFile, html, "utf8");
console.log(JSON.stringify({ outFile, bytes: Buffer.byteLength(html, "utf8") }));
