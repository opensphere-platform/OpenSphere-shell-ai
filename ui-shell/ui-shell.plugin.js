// ─────────────────────────────────────────────────────────────────────────
// AI — OpenSphere subShell 진입점 (SDK 표준 골격).
//   셸 계약: ESM activate/deactivate. light DOM. Angular Element <osp-ai-shell>를 셸 본문에 주입.
//   server.js가 /api/k8s/* 프록시 + WS exec + /app(번들) 서빙.
// ─────────────────────────────────────────────────────────────────────────
const TAG = 'osp-ai-shell'; // www/main.js(Angular Elements)가 customElements.define(TAG)
let injected = false;

function injectOnce(base) {
  if (injected) return;
  injected = true;
  window.__OSP_NG_API_BASE__ = base; // legacy SDK skeleton compatibility
  window.__OSP_AI_API_BASE__ = base; // AI dashboard REST endpoints
  const v = `?v=${Date.now()}`; // 재배포 번들 즉시 반영(PoC 캐시버스터)
  const css = document.createElement('link');
  css.rel = 'stylesheet'; css.href = `${base}/app/styles.css${v}`;
  css.setAttribute('data-osp-plugin', 'ai');
  document.head.appendChild(css);
  const s = document.createElement('script');
  s.type = 'module'; s.src = `${base}/app/main.js${v}`;
  document.head.appendChild(s);
}

export function activate(ctx) {
  const base = (ctx.api?.baseUrl ?? '').replace(/\/$/, '');
  injectOnce(base);
  ctx.extensions.registerPage({
    id: ctx.pluginId,
    title: 'OpenSphere AI Hub',
    navBand: 'Operate',
    elementTag: TAG,
  });
}

export function deactivate() {}
