// OpenSphere AI — CONSTITUTION-0003 Production subShell reference adapter.
const TAG = 'osp-ai-shell';
const RELEASE = '1.1.0-edge.1';
let injected = false;
let activeContext = null;

function injectOnce(base) {
  if (injected) return;
  injected = true;
  window.__OSP_NG_API_BASE__ = base;
  window.__OSP_AI_API_BASE__ = base;
  const css = document.createElement('link');
  css.rel = 'stylesheet';
  css.href = `${base}/app/styles.css?v=${RELEASE}`;
  css.setAttribute('data-osp-plugin', 'ai');
  document.head.appendChild(css);
  const script = document.createElement('script');
  script.type = 'module';
  script.src = `${base}/app/main.js?v=${RELEASE}`;
  script.setAttribute('data-osp-plugin', 'ai');
  document.head.appendChild(script);
}

const navigation = [
  { id: 'ai-operate', label: 'AI Operations', children: [
    { id: 'ai-overview', label: 'Overview', route: '/p/ai' },
    { id: 'ai-workbenches', label: 'Workbenches', route: '/p/ai/workbenches' },
    { id: 'ai-pipelines', label: 'Pipelines', route: '/p/ai/pipelines' },
    { id: 'ai-training', label: 'Training', route: '/p/ai/training/jobs' },
    { id: 'ai-models', label: 'Models', route: '/p/ai/models/registry' },
    { id: 'ai-inference', label: 'Inference', route: '/p/ai/inference' },
    { id: 'ai-evaluation', label: 'Evaluation', route: '/p/ai/evaluation/jobs' },
    { id: 'ai-monitoring', label: 'Monitoring', route: '/p/ai/monitoring/trustyai' },
  ] },
];

async function contributeManual(ctx) {
  if (!ctx.extensions.manual || !ctx.api?.fetch) {
    throw new Error('Manual contribution contract is unavailable');
  }
  const response = await ctx.api.fetch('plugins/manual/ai.ko.md', { cache: 'no-store' });
  if (!response.ok) throw new Error(`AI Manual fetch failed (HTTP ${response.status})`);
  const content = await response.text();
  ctx.extensions.manual.contribute({
    sourceId: 'opensphere-ai-hub',
    title: 'OpenSphere AI Hub',
    locale: 'ko-KR',
    route: '/p/ai',
    sourcePath: 'ui-shell/manual/ai.ko.md',
    content,
    tags: ['ai', 'workbench', 'pipeline', 'training', 'model', 'inference', 'evaluation', 'monitoring'],
  });
}

export async function activate(ctx) {
  activeContext = ctx;
  const base = (ctx.api?.baseUrl ?? '').replace(/\/$/, '');
  const contexts = window.__OPENSPHERE_HOST_CONTEXTS__ ||= Object.create(null);
  contexts.ai = { api: { baseUrl: base, fetch: ctx.api?.fetch }, routing: ctx.routing };
  injectOnce(base);
  ctx.extensions.registerPage?.({ id: ctx.pluginId, title: 'OpenSphere AI Hub', navBand: 'Operate', elementTag: TAG });
  ctx.extensions.nav?.contribute(navigation);
  ctx.extensions.search?.contribute({
    async query(q) {
      const response = await ctx.api.fetch(`search?q=${encodeURIComponent(q)}`);
      if (!response.ok) return [];
      const body = await response.json();
      return Array.isArray(body.items) ? body.items : [];
    },
  });
  await contributeManual(ctx);
  ctx.notify?.publish({
    title: 'OpenSphere AI Hub ready',
    detail: 'Production subShell capabilities are connected to the Main Shell.',
    severity: 'success',
    persistent: false,
    category: 'AI lifecycle',
    route: '/p/ai',
    topic: 'ai.subshell.ready',
    dedupKey: `ai-ready-${RELEASE}`,
  });
}

export function deactivate() {
  activeContext?.extensions.nav?.clear();
  activeContext?.extensions.search?.clear();
  activeContext?.extensions.manual?.clear();
  activeContext?.notify?.clear();
  if (window.__OPENSPHERE_HOST_CONTEXTS__) delete window.__OPENSPHERE_HOST_CONTEXTS__.ai;
  document.querySelectorAll('[data-osp-plugin="ai"]').forEach((node) => node.remove());
  delete window.__OSP_NG_API_BASE__;
  delete window.__OSP_AI_API_BASE__;
  activeContext = null;
  injected = false;
}
