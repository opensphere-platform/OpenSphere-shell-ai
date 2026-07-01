const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const WebSocket = require('ws');

const route = process.env.OAH_LIVE_ROUTE || 'https://console.opensphere.dev/ai/cluster-settings/support-services';
const token = process.env.OAH_ID_TOKEN || '';

function log(message) {
  console.log(`[support-services-live-browser] ${message}`);
}

function fail(message) {
  console.error(`[support-services-live-browser] ${message}`);
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
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/usr/bin/microsoft-edge',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
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

function httpJson(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
        } catch (error) {
          reject(error);
        }
      });
    }).on('error', reject);
  });
}

async function waitForCdp(port, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const version = await httpJson(`http://127.0.0.1:${port}/json/version`);
      if (version.webSocketDebuggerUrl) return version;
    } catch {
      // Browser is still starting.
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error('Timed out waiting for Chrome DevTools Protocol.');
}

function cdpClient(wsUrl) {
  const ws = new WebSocket(wsUrl);
  let id = 0;
  const pending = new Map();
  const events = [];
  ws.on('message', (data) => {
    const msg = JSON.parse(data.toString());
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) reject(new Error(msg.error.message || JSON.stringify(msg.error)));
      else resolve(msg);
    } else if (msg.method) {
      events.push(msg);
      if (events.length > 100) events.shift();
    }
  });
  return new Promise((resolve, reject) => {
    ws.once('open', () => {
      resolve({
        events,
        send(method, params = {}) {
          const msgId = ++id;
          ws.send(JSON.stringify({ id: msgId, method, params }));
          return new Promise((res, rej) => pending.set(msgId, { resolve: res, reject: rej }));
        },
        close() {
          ws.close();
        },
      });
    });
    ws.once('error', reject);
  });
}

async function stopBrowser(browser) {
  if (!browser || browser.exitCode !== null) return;
  browser.kill();
  await new Promise((resolve) => browser.once('exit', resolve));
}

async function removeProfileDir(userDataDir) {
  await fs.promises.rm(userDataDir, { recursive: true, force: true }).catch(() => undefined);
}

async function waitForRuntime(client, expression, label, timeoutMs = 45000) {
  const deadline = Date.now() + timeoutMs;
  let last;
  while (Date.now() < deadline) {
    const result = await client.send('Runtime.evaluate', { expression, returnByValue: true }).catch((error) => ({ error }));
    last = result.error ? result.error.message : result.result?.value;
    if (last) return last;
    await new Promise((resolve) => setTimeout(resolve, 750));
  }
  const debug = await client.send('Runtime.evaluate', {
    expression: `(() => ({
      url: location.href,
      title: document.title,
      text: (document.body.innerText || '').replace(/\\s+/g, ' ').slice(0, 2000),
      missing: window.__oahLiveMissingSupportTexts || [],
      fetchErrors: window.__oahLiveFetchErrors || [],
      events: (window.__oahLiveBrowserEvents || []).slice(-10)
    }))()`,
    returnByValue: true,
  }).catch(() => ({ result: { value: {} } }));
  throw new Error(`${label} did not become true. Last=${JSON.stringify(last)} Debug=${JSON.stringify(debug.result.value)}`);
}

async function main() {
  if (!token) {
    log('skipped; set OAH_ID_TOKEN to run authenticated live browser verification.');
    return;
  }

  const browserPath = findBrowser();
  assert(browserPath, 'Chrome or Edge executable was not found. Set CHROME_PATH to run live browser verification.');

  const cdpPort = await freePort();
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'oah-live-browser-'));
  const browser = spawn(browserPath, [
    '--headless=new',
    '--disable-gpu',
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-extensions',
    '--ignore-certificate-errors',
    `--remote-debugging-port=${cdpPort}`,
    `--user-data-dir=${userDataDir}`,
    'about:blank',
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
    await client.send('Page.addScriptToEvaluateOnNewDocument', {
      source: `
        (() => {
          const token = ${JSON.stringify(token)};
          window.__OSP_ID_TOKEN__ = token;
          window.__OPENSPHERE_ID_TOKEN__ = token;
          window.__OS_AUTH__ = { token };
          window.__oahLiveFetchErrors = [];
          const originalFetch = window.fetch.bind(window);
          window.fetch = (input, init = {}) => {
            const url = typeof input === 'string' ? input : (input && input.url) || '';
            const nextInit = { ...init };
            if (String(url).includes('/api/plugins/ai/')) {
              nextInit.headers = { ...(init.headers || {}), 'x-os-id-token': token };
            }
            return originalFetch(input, nextInit).catch((error) => {
              window.__oahLiveFetchErrors.push(String(error && error.message || error));
              throw error;
            });
          };
          window.addEventListener('error', (event) => {
            window.__oahLiveBrowserEvents = window.__oahLiveBrowserEvents || [];
            window.__oahLiveBrowserEvents.push(String(event.message || event.error || 'error'));
          });
        })();
      `,
    });

    await client.send('Page.navigate', { url: route });
    await waitForRuntime(client, `location.href.includes('/ai/cluster-settings/support-services')`, 'support-services route');
    await waitForRuntime(client, `((document.body.innerText || '') + ' ' + (document.body.textContent || '')).toLowerCase().includes('oah product flow readiness')`, 'product flow panel');

    const requiredTexts = [
      'oah product flow readiness',
      'gpu training smoke',
      'backbone pgvector memory',
      'kserve / knative serving',
      'upstream parity inventory',
      'data science pipelines operator only',
      'traffic=100%',
      'configure backbone foundation',
    ];
    await waitForRuntime(client, `(() => {
      const text = ((document.body.innerText || '') + ' ' + (document.body.textContent || '')).toLowerCase();
      const missing = ${JSON.stringify(requiredTexts)}.filter((item) => !text.includes(item));
      window.__oahLiveMissingSupportTexts = missing;
      return missing.length === 0;
    })()`, 'live support-services product-flow evidence');

    const rendered = await client.send('Runtime.evaluate', {
      expression: `(() => {
        const text = ((document.body.innerText || '') + ' ' + (document.body.textContent || '')).toLowerCase();
        const buttons = [...document.querySelectorAll('button')].map((button) => ({
          text: (button.textContent || '').replace(/\\s+/g, ' ').trim(),
          disabled: button.disabled,
        }));
        return {
          url: location.href,
          hasReady: text.includes('ready'),
          missing: window.__oahLiveMissingSupportTexts || [],
          fetchErrors: window.__oahLiveFetchErrors || [],
          buttons,
        };
      })()`,
      returnByValue: true,
    });
    const value = rendered.result.value;
    assert(value.missing.length === 0, `Missing live rendered text: ${value.missing.join(', ')}`);
    assert(value.fetchErrors.length === 0, `Live browser fetch errors: ${value.fetchErrors.join('; ')}`);
    assert(value.buttons.some((button) => button.text.includes('Refresh') || button.text.includes('REFRESH')), 'Refresh button was not rendered.');

    log(`checks passed route=${value.url}`);
  } finally {
    if (client) client.close();
    await stopBrowser(browser);
    await removeProfileDir(userDataDir);
  }
}

main().catch((error) => {
  fail(error.message || String(error));
});
