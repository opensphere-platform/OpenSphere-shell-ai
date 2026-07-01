const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const WebSocket = require('ws');

const root = path.resolve(__dirname, '..');
const dist = path.resolve(root, 'dist', 'ai', 'browser');

function fail(message) {
  console.error(`[support-services-browser] ${message}`);
  process.exitCode = 1;
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function findBrowser() {
  const candidates = [
    process.env.CHROME_PATH,
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  ].filter(Boolean);
  return candidates.find((candidate) => fs.existsSync(candidate));
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

function sendJson(res, status, body) {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'access-control-allow-origin': '*',
    'access-control-allow-headers': '*',
    'access-control-allow-methods': 'GET,POST,OPTIONS',
  });
  res.end(JSON.stringify(body));
}

function supportServicesPayload() {
  const generatedAt = new Date('2026-07-01T00:00:00.000Z').toISOString();
  return {
    generatedAt,
    phase: 'Ready',
    summary: { total: 10, ready: 7, configured: 2, missing: 1, requiredMissing: 0 },
    backbone: {
      phase: 'Ready',
      ready: true,
      namespace: 'opensphere-backbone',
      components: [
        { id: 'postgres', label: 'PostgreSQL', ready: true, phase: 'Ready', endpoint: 'backbone-postgres.opensphere-backbone.svc:5432' },
        { id: 'rustfs', label: 'RustFS', ready: true, phase: 'Ready', endpoint: 'http://backbone-rustfs.opensphere-backbone.svc:9000' },
        { id: 'gitea', label: 'Gitea', ready: true, phase: 'Ready', endpoint: 'http://backbone-gitea.opensphere-backbone.svc:3000' },
      ],
      defaults: {
        objectStorage: {
          endpoint: 'http://backbone-rustfs.opensphere-backbone.svc:9000',
          bucket: 'ai-hub',
          region: 'us-east-1',
          secretName: 'ai-hub-backbone-rustfs',
          useTls: false,
          insecureSkipTlsVerify: true,
        },
        metadata: {
          provider: 'postgres',
          host: 'backbone-postgres.opensphere-backbone.svc.cluster.local',
          port: '5432',
          database: 'ai_hub',
          username: 'ai_hub',
          sslMode: 'disable',
        },
      },
      consumer: {
        claim: { name: 'ai-hub', namespace: 'opensphere-system', phase: 'Bound', ready: true },
        bindings: { postgresSecretReady: true, rustfsSecretReady: true },
      },
    },
    setupPrerequisites: [],
    configurationPages: [
      { id: 'backbone', service: 'Console Backbone provider', page: 'Console / Backbone', mode: 'external', action: 'Open Backbone', requiredBefore: ['Metadata DB', 'Object storage'], route: '/backbone' },
      { id: 'pipelines', service: 'Data Science Pipelines / KFP', page: 'Cluster settings / Support services', mode: 'native fallback', action: 'Preview pipelines foundation', requiredBefore: ['Metadata DB', 'Object storage'], route: '/ai/cluster-settings/support-services' },
    ],
    installPlan: [
      { order: 1, id: 'backbone', title: 'Console Backbone provider', menu: 'Console / Backbone', status: 'Ready', action: 'Consume Backbone contract', blocks: ['Metadata DB', 'Object storage'] },
      { order: 2, id: 'pipelines', title: 'Data Science Pipelines / KFP', menu: 'Support services', status: 'Ready', action: 'Bind PostgreSQL and RustFS', blocks: ['PipelineRun', 'Artifacts'] },
    ],
    upstreamParity: {
      generatedAt,
      phase: 'Partial',
      summary: { total: 7, ready: 3, warnings: 1, missing: 3, required: 5, requiredMissing: 2 },
      checks: [
        { id: 'odh-operator', label: 'ODH/RHOAI operator', required: true, status: 'Warning', ready: false, evidence: 'Mock opendatahub namespace has Data Science Pipelines Operator only; full ODH/RHOAI operator evidence was not found.', nextAction: 'Install the ODH/RHOAI Operator before claiming full upstream substrate parity.', resources: [] },
        { id: 'datasciencecluster', label: 'DataScienceCluster', required: true, status: 'NotInstalled', ready: false, evidence: 'DataScienceCluster CRD is not installed.', nextAction: 'Install the ODH/RHOAI Operator and create a DataScienceCluster for full upstream parity.', resources: [] },
        { id: 'dspa-kfp', label: 'Data Science Pipelines / KFP', required: true, status: 'Ready', ready: true, evidence: 'Mock DSPA is ready.', nextAction: 'Keep KFP verified.', resources: [] },
        { id: 'knative-serving', label: 'Knative Serving', required: true, status: 'Ready', ready: true, evidence: 'Mock Knative is ready.', nextAction: 'Run route checks.', resources: [] },
        { id: 'kserve-serving', label: 'KServe inference', required: true, status: 'Ready', ready: true, evidence: 'Mock KServe route/revision/traffic path validated with traffic=100%.', nextAction: 'Run serving e2e.', resources: [] },
        { id: 'model-registry', label: 'Upstream Model Registry', required: false, status: 'NotInstalled', ready: false, evidence: 'Mock Model Registry is absent.', nextAction: 'Install when parity is required.', resources: [] },
        { id: 'trustyai', label: 'TrustyAI monitoring', required: false, status: 'NotInstalled', ready: false, evidence: 'Mock TrustyAI is absent.', nextAction: 'Install when monitoring is required.', resources: [] },
      ],
    },
    items: [
      { id: 'backbone', label: 'Console Backbone provider', category: 'Core substrate', required: true, requiredFor: ['Metadata DB', 'Object storage'], phase: 'Ready', ready: true, installed: true, configured: true, evidence: 'Mock Backbone claim is bound.', nextStep: 'None', resources: [] },
      { id: 'metadata-store', label: 'Metadata PostgreSQL database', category: 'Metadata', required: true, requiredFor: ['KFP metadata', 'Model Registry', 'TrustyAI storage'], phase: 'Ready', ready: true, installed: true, configured: true, evidence: 'Mock PostgreSQL binding is ready.', nextStep: 'None', resources: [] },
      { id: 'object-storage', label: 'S3-compatible object storage', category: 'Artifacts', required: true, requiredFor: ['KServe storageUri', 'KFP artifact store'], phase: 'Ready', ready: true, installed: true, configured: true, evidence: 'Mock RustFS binding is ready.', nextStep: 'None', resources: [] },
      { id: 'pipelines', label: 'Data Science Pipelines / KFP', category: 'Pipelines', required: true, requiredFor: ['PipelineRun', 'Experiments', 'Artifacts'], phase: 'Ready', ready: true, installed: true, configured: true, evidence: 'Mock pipeline runtime is ready.', nextStep: 'None', resources: [] },
    ],
  };
}

function foundationPayload() {
  return {
    generatedAt: new Date('2026-07-01T00:00:00.000Z').toISOString(),
    phase: 'Ready',
    summary: { total: 8, ready: 7, configured: 2, required: 6, requiredReady: 6, requiredMissing: 0, optionalReady: 1 },
    items: [
      { id: 'backbone', label: 'Console Backbone provider', category: 'Core substrate', required: true, source: 'Backbone', phase: 'Ready', ready: true, available: true, usedBy: ['Metadata DB', 'Object storage'], evidence: 'Mock Backbone provider ready.', action: 'None', resources: [] },
      { id: 'pipelines', label: 'Data Science Pipelines / KFP', category: 'Pipelines', required: true, source: 'Native fallback', phase: 'Ready', ready: true, available: true, usedBy: ['PipelineRun', 'Artifacts'], evidence: 'Mock KFP ready.', action: 'None', resources: [] },
    ],
    supportServices: supportServicesPayload(),
  };
}

function foundationPreview(label) {
  return {
    phase: 'Ready',
    generatedAt: new Date('2026-07-01T00:00:00.000Z').toISOString(),
    summary: { ready: 3, configured: 1, required: 3, total: 3 },
    checks: [
      { id: 'metadata', label: 'Metadata PostgreSQL', status: 'Ready', evidence: 'Backbone PostgreSQL mock is bound.', nextStep: 'None', resources: [] },
      { id: 'object-storage', label: 'Object storage', status: 'Ready', evidence: 'Backbone RustFS mock is bound.', nextStep: 'None', resources: [] },
      { id: 'runtime', label, status: 'Ready', evidence: 'Mock runtime contract ready.', nextStep: 'None', resources: [] },
    ],
    installOptions: [
      { id: 'native', label: 'OpenSphere-native fallback', recommended: true, phase: 'Ready', action: 'No action needed in browser smoke.', manifests: [{ kind: 'Mock', metadata: { name: label } }] },
    ],
  };
}

function createHarnessServer(port) {
  const html = `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <base href="/">
  <title>OAH Support Services Browser Smoke</title>
  <script>
    window.__OSP_AI_API_BASE__ = '';
    window.__OSP_NG_API_BASE__ = '';
    window.__oahFetchLog = [];
    const __oahOriginalFetch = window.fetch.bind(window);
    window.fetch = async (...args) => {
      const response = await __oahOriginalFetch(...args);
      try {
        const url = String(args[0]);
        if (url.includes('/admin/native/support-services') || url.includes('/admin/native/foundation-services')) {
          const body = await response.clone().json();
          const parity = body.upstreamParity || body.supportServices?.upstreamParity;
          window.__oahFetchLog.push({
            url,
            status: response.status,
            phase: body.phase,
            summary: body.summary,
            upstreamParity: parity ? {
              phase: parity.phase,
              summary: parity.summary,
              checks: (parity.checks || []).map((check) => ({ id: check.id, status: check.status, evidence: check.evidence })),
            } : undefined,
          });
        }
      } catch {}
      return response;
    };
    window.history.replaceState({}, '', '/ai/cluster-settings/support-services');
  </script>
  <link rel="stylesheet" href="/app/styles.css">
</head>
<body>
  <osp-ai-shell></osp-ai-shell>
  <script type="module" src="/app/main.js"></script>
</body>
</html>`;

  return http.createServer((req, res) => {
    const url = new URL(req.url || '/', `http://127.0.0.1:${port}`);
    if (req.method === 'OPTIONS') return sendJson(res, 204, {});
    if (url.pathname === '/ai/cluster-settings/support-services' || url.pathname === '/') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      res.end(html);
      return;
    }
    if (url.pathname === '/app/main.js' || url.pathname === '/app/styles.css') {
      const file = path.join(dist, path.basename(url.pathname));
      const type = url.pathname.endsWith('.css') ? 'text/css; charset=utf-8' : 'text/javascript; charset=utf-8';
      res.writeHead(200, { 'content-type': type });
      fs.createReadStream(file).pipe(res);
      return;
    }
    if (url.pathname.startsWith('/app/assets/')) {
      const file = path.join(dist, url.pathname.replace(/^\/app\//, ''));
      if (fs.existsSync(file)) {
        res.writeHead(200);
        fs.createReadStream(file).pipe(res);
      } else {
        res.writeHead(404);
        res.end('not found');
      }
      return;
    }
    if (url.pathname === '/admin/native/support-services') return sendJson(res, 200, supportServicesPayload());
    if (url.pathname === '/admin/native/upstream-parity') return sendJson(res, 200, supportServicesPayload().upstreamParity);
    if (url.pathname === '/admin/native/foundation-services') return sendJson(res, 200, foundationPayload());
    if (url.pathname === '/admin/native/foundation-services/configure') return sendJson(res, 200, { phase: 'Configured', foundationServices: foundationPayload(), supportServices: supportServicesPayload() });
    if (url.pathname === '/admin/native/support-services/pipelines/preview') return sendJson(res, 200, foundationPreview('Data Science Pipelines / KFP'));
    if (url.pathname === '/admin/native/support-services/model-registry/preview') return sendJson(res, 200, foundationPreview('Model Registry'));
    if (url.pathname === '/admin/native/support-services/model-registry/configure') return sendJson(res, 200, { phase: 'NativePostgresReady', steps: [{ id: 'native-registry-postgres', label: 'Backbone PostgreSQL model registry schema', phase: 'Succeeded', detail: 'Mock model registry configured.' }], preview: foundationPreview('Model Registry') });
    if (url.pathname === '/admin/native/support-services/observability/preview') return sendJson(res, 200, foundationPreview('TrustyAI / Monitoring'));
    if (url.pathname === '/admin/native/support-services/distributed/preview') return sendJson(res, 200, foundationPreview('Kueue / Ray distributed scheduler'));
    if (url.pathname.endsWith('/preview')) return sendJson(res, 200, { phase: 'ReadyToApply', summary: { manifests: 1, namespaceExists: true, passwordProvided: false, credentialsProvided: false, purposes: 3 }, manifests: [{ kind: 'Secret', metadata: { name: 'mock' } }] });
    if (url.pathname === '/training/compute') return sendJson(res, 200, { items: [] });
    if (url.pathname.startsWith('/admin/') || url.pathname.startsWith('/resources/') || url.pathname.startsWith('/memory/') || url.pathname.startsWith('/pipelines/') || url.pathname.startsWith('/models/')) {
      return sendJson(res, 200, { phase: 'Ready', generatedAt: new Date().toISOString(), summary: {}, items: [], records: [], components: [], crds: [], prerequisites: [] });
    }
    res.writeHead(404);
    res.end('not found');
  });
}

function httpJson(url, method = 'GET') {
  return new Promise((resolve, reject) => {
    const req = http.request(url, { method }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => {
        try {
          resolve(JSON.parse(body));
        } catch (error) {
          reject(error);
        }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

function cdpClient(wsUrl) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl);
    let id = 0;
    const pending = new Map();
    const events = [];
    ws.on('open', () => {
      ws.on('message', (raw) => {
        const message = JSON.parse(String(raw));
        if (!message.id) {
          if (message.method === 'Runtime.exceptionThrown' || message.method === 'Log.entryAdded') {
            events.push(message);
          }
          return;
        }
        const entry = pending.get(message.id);
        if (!entry) return;
        pending.delete(message.id);
        if (message.error) entry.reject(new Error(message.error.message));
        else entry.resolve(message.result);
      });
      resolve({
        send(method, params = {}) {
          return new Promise((resolveCommand, rejectCommand) => {
            const commandId = ++id;
            pending.set(commandId, { resolve: resolveCommand, reject: rejectCommand });
            ws.send(JSON.stringify({ id: commandId, method, params }));
          });
        },
        close() {
          ws.close();
        },
        events,
      });
    });
    ws.on('error', reject);
  });
}

function stopBrowser(child) {
  return new Promise((resolve) => {
    if (!child || child.killed) return resolve();
    const done = () => resolve();
    child.once('exit', done);
    if (process.platform === 'win32') {
      const killer = spawn('taskkill.exe', ['/pid', String(child.pid), '/t', '/f'], { stdio: 'ignore' });
      killer.once('exit', () => {
        setTimeout(resolve, 500);
      });
      return;
    }
    child.kill('SIGTERM');
    setTimeout(() => {
      if (!child.killed) child.kill('SIGKILL');
      resolve();
    }, 1000);
  });
}

async function removeProfileDir(dir) {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }
}

async function waitForCdp(port) {
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    try {
      const version = await httpJson(`http://127.0.0.1:${port}/json/version`);
      if (version.Browser) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error('Browser debugging endpoint did not become ready.');
}

async function waitForRuntime(client, expression, label) {
  const deadline = Date.now() + 20000;
  let last;
  while (Date.now() < deadline) {
    const result = await client.send('Runtime.evaluate', {
      expression,
      awaitPromise: true,
      returnByValue: true,
    });
    last = result.result?.value;
    if (last) return last;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  const debug = await client.send('Runtime.evaluate', {
    expression: `(() => {
      const tables = [...document.querySelectorAll('table')].map((table) => ({
        headers: [...table.querySelectorAll('th')].map((cell) => (cell.innerText || '').trim()),
        rows: [...table.querySelectorAll('tbody tr')].slice(0, 8).map((row) => ({
          innerText: (row.innerText || '').replace(/\\s+/g, ' ').trim(),
          textContent: (row.textContent || '').replace(/\\s+/g, ' ').trim(),
          html: (row.outerHTML || '').replace(/\\s+/g, ' ').trim().slice(0, 600),
        })),
      }));
      return { url: location.href, missing: window.__oahMissingSupportTexts || [], fetchLog: window.__oahFetchLog || [], tables, innerText: (document.body.innerText || '').slice(0, 1600), textContent: (document.body.textContent || '').replace(/\\s+/g, ' ').trim().slice(0, 1600), html: document.body.innerHTML.slice(0, 1200) };
    })()`,
    returnByValue: true,
  }).catch(() => ({ result: { value: {} } }));
  throw new Error(`${label} did not become true. Last value: ${JSON.stringify(last)} Debug=${JSON.stringify({
    ...debug.result.value,
    browserEvents: (client.events || []).slice(-5),
  })}`);
}

async function main() {
  assert(fs.existsSync(path.join(dist, 'main.js')), 'dist/ai/browser/main.js is missing. Run npm run build first.');
  assert(fs.existsSync(path.join(dist, 'styles.css')), 'dist/ai/browser/styles.css is missing. Run npm run build first.');
  const browserPath = findBrowser();
  assert(browserPath, 'Chrome or Edge executable was not found. Set CHROME_PATH to run browser smoke verification.');

  const harnessPort = await freePort();
  const cdpPort = await freePort();
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'oah-browser-smoke-'));
  const server = createHarnessServer(harnessPort);
  await new Promise((resolve) => server.listen(harnessPort, '127.0.0.1', resolve));

  const browser = spawn(browserPath, [
    '--headless=new',
    '--disable-gpu',
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-extensions',
    `--remote-debugging-port=${cdpPort}`,
    `--user-data-dir=${userDataDir}`,
    `http://127.0.0.1:${harnessPort}/ai/cluster-settings/support-services`,
  ], { stdio: 'ignore' });

  let client;
  try {
    await waitForCdp(cdpPort);
    const target = await httpJson(`http://127.0.0.1:${cdpPort}/json/list`);
    const page = target.find((item) => item.type === 'page') || target[0];
    assert(page?.webSocketDebuggerUrl, 'No debuggable page was created.');
    client = await cdpClient(page.webSocketDebuggerUrl);
    await client.send('Page.enable');
    await client.send('Runtime.enable');
    await client.send('Log.enable').catch(() => undefined);

    await waitForRuntime(client, `Boolean(customElements.get('osp-ai-shell'))`, 'custom element registration');
    await waitForRuntime(client, `Boolean(document.querySelector('osp-ai-shell'))`, 'AI shell element');
    await waitForRuntime(client, `(document.body.innerText || '').includes('OAH support services')`, 'Support services tab');

    const requiredTexts = [
      'oah support services',
      'upstream parity inventory',
      'odh/rhoai operator',
      'data science pipelines operator only',
      'traffic=100%',
      'datasciencecluster',
      'prerequisite services',
      'console backbone provider',
      'apply oah claim',
      'bind issued secrets',
      'preview pipelines foundation',
      'configure registry foundation',
      'metadata credential bootstrap',
      'object storage bootstrap',
    ];
    await waitForRuntime(client, `(() => {
      const text = ((document.body.innerText || '') + ' ' + (document.body.textContent || '')).toLowerCase();
      const missing = ${JSON.stringify(requiredTexts)}.filter((item) => !text.includes(item));
      window.__oahMissingSupportTexts = missing;
      return missing.length === 0;
    })()`, 'Support services controls');
    const rendered = await client.send('Runtime.evaluate', {
      expression: `(() => {
        const text = ((document.body.innerText || '') + ' ' + (document.body.textContent || '')).toLowerCase();
        const required = ${JSON.stringify(requiredTexts)};
        const buttons = [...document.querySelectorAll('button')].map((button) => ({
          text: (button.textContent || '').replace(/\\s+/g, ' ').trim(),
          disabled: button.disabled,
        }));
        return { missing: required.filter((item) => !text.includes(item)), buttons };
      })()`,
      returnByValue: true,
    });
    const renderedValue = rendered.result.value;
    assert(renderedValue.missing.length === 0, `Missing rendered text: ${renderedValue.missing.join(', ')}`);
    for (const label of ['Use Backbone defaults', 'Apply OAH claim', 'Bind issued Secrets', 'Preview pipelines foundation']) {
      const button = renderedValue.buttons.find((item) => item.text.includes(label));
      assert(button, `Button "${label}" was not rendered.`);
      assert(!button.disabled, `Button "${label}" was unexpectedly disabled.`);
    }

    const clickResult = await client.send('Runtime.evaluate', {
      expression: `(() => {
        const button = [...document.querySelectorAll('button')].find((item) => (item.textContent || '').includes('Preview pipelines foundation'));
        if (!button || button.disabled) return false;
        button.click();
        return true;
      })()`,
      returnByValue: true,
    });
    assert(clickResult.result.value === true, 'Preview pipelines foundation button could not be clicked.');
    await waitForRuntime(client, `(document.body.innerText || '').includes('Pipelines foundation preview generated')`, 'pipelines preview action message');

    console.log('[support-services-browser] browser render and click-through checks passed');
  } finally {
    if (client) client.close();
    await stopBrowser(browser);
    server.close();
    await removeProfileDir(userDataDir);
  }
}

main().catch((error) => {
  fail(error.message || String(error));
});
