const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const WebSocket = require('ws');

const route = process.env.OAH_LIVE_ROUTE || 'https://console.opensphere.dev/p/ai/cluster-settings/support-services';
const token = process.env.OAH_ID_TOKEN || '';
const requiredIssuer = process.env.OAH_REQUIRED_TOKEN_ISSUER || 'https://auth.console.opensphere.dev/oauth2/openid/opensphere-console';
const requiredAudience = process.env.OAH_REQUIRED_TOKEN_AUDIENCE || 'opensphere-console';
const identityGroupClaimKeys = ['groups', 'groups_name', 'group_names', 'roles'];
const adminGroups = (process.env.OSP_ADMIN_GROUPS || 'opensphere-console-admins,opensphere-admins,system:masters,cluster-admins')
  .split(',')
  .map((item) => item.trim())
  .filter(Boolean);

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

function decodeJwtPayload(jwt) {
  const payload = String(jwt || '').split('.')[1] || '';
  assert(payload, 'OAH_ID_TOKEN is not a JWT with a payload segment.');
  const padded = payload.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(payload.length / 4) * 4, '=');
  return JSON.parse(Buffer.from(padded, 'base64').toString('utf8'));
}

function decodeJwtHeader(jwt) {
  const parts = String(jwt || '').split('.');
  assert(parts[2], 'OAH_ID_TOKEN is not a signed JWT with a signature segment.');
  const padded = (parts[0] || '').replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil((parts[0] || '').length / 4) * 4, '=');
  const header = JSON.parse(Buffer.from(padded, 'base64').toString('utf8'));
  assert(header.alg && String(header.alg).toLowerCase() !== 'none', 'OAH_ID_TOKEN must use a signed JWT alg; alg=none is not accepted.');
  return header;
}

function claimStrings(value) {
  if (Array.isArray(value)) return value.flatMap((item) => claimStrings(item));
  if (typeof value === 'string') return value.split(/[,\s]+/).map((item) => item.trim()).filter(Boolean);
  if (value && typeof value === 'object') return Object.values(value).flatMap((item) => claimStrings(item));
  return [];
}

function identityGroupsFromPayload(payload) {
  const groups = [];
  for (const key of identityGroupClaimKeys) groups.push(...claimStrings(payload[key]));
  groups.push(...claimStrings(payload.realm_access?.roles));
  for (const resource of Object.values(payload.resource_access || {})) groups.push(...claimStrings(resource?.roles));
  return [...new Set(groups.filter(Boolean))];
}

function identityGroupAliases(value) {
  const aliases = new Set();
  for (const group of claimStrings(value)) {
    aliases.add(group);
    const trimmed = group.replace(/^\/+/, '');
    if (trimmed) aliases.add(trimmed);
    const leaf = trimmed.split('/').filter(Boolean).pop();
    if (leaf) aliases.add(leaf);
  }
  return [...aliases];
}

function verifyTokenWithHelper() {
  const helper = path.join(__dirname, 'verify-oah-id-token.js');
  const result = spawnSync(process.execPath, ['--use-system-ca', helper], { encoding: 'utf8', env: process.env });
  const text = `${result.stdout || ''}\n${result.stderr || ''}`.trim();
  const jsonLine = text.split(/\r?\n/).findLast((line) => line.trim().startsWith('{'));
  let parsed = null;
  if (jsonLine) {
    try {
      parsed = JSON.parse(jsonLine);
    } catch {
      parsed = null;
    }
  }
  assert(result.status === 0 && parsed?.ok === true, parsed?.error || text || 'OAH_ID_TOKEN verification helper failed.');
  return parsed;
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
    const result = await client.send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }).catch((error) => ({ error }));
    last = result.error ? result.error.message : result.result?.result?.value;
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
  }).catch(() => ({ result: { result: { value: {} } } }));
  throw new Error(`${label} did not become true. Last=${JSON.stringify(last)} Debug=${JSON.stringify(debug.result.result.value)}`);
}

async function main() {
  if (!token) {
    log('skipped; set OAH_ID_TOKEN to run authenticated live browser verification.');
    return;
  }
  const verifiedToken = verifyTokenWithHelper();
  decodeJwtHeader(token);
  const payload = decodeJwtPayload(token);
  const tokenGroups = identityGroupsFromPayload(payload);
  const tokenGroupAliases = identityGroupAliases(tokenGroups);
  const tokenLooksAdmin = identityGroupAliases(adminGroups).some((group) => tokenGroupAliases.includes(group));
  assert(!payload.exp || payload.exp > Math.floor(Date.now() / 1000), 'OAH_ID_TOKEN is expired.');
  if (requiredIssuer) {
    assert(payload.iss === requiredIssuer, `OAH_ID_TOKEN issuer mismatch: expected ${requiredIssuer}, got ${payload.iss || 'missing'}.`);
  }
  if (requiredAudience) {
    assert(claimStrings(payload.aud).includes(requiredAudience), `OAH_ID_TOKEN audience mismatch: expected ${requiredAudience}.`);
  }
  assert(tokenGroups.length > 0, 'OAH_ID_TOKEN does not contain any supported group claim: groups, groups_name, group_names, roles, realm_access.roles, or resource_access.*.roles.');
  log(`token subject=${payload.sub || payload.preferred_username || payload.email || 'unknown'} groups=${tokenGroups.length} adminGroup=${tokenLooksAdmin} signatureVerified=${verifiedToken.signatureVerified}`);

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
          const authority = 'https://auth.console.opensphere.dev/oauth2/openid/opensphere-console';
          const clientId = 'opensphere-console';
          const decode = (part) => JSON.parse(atob(part.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(part.length / 4) * 4, '=')));
          const profile = decode(token.split('.')[1] || '');
          try {
            window.sessionStorage.setItem('oidc.user:' + authority + ':' + clientId, JSON.stringify({
              id_token: token,
              access_token: token,
              token_type: 'Bearer',
              scope: 'openid profile email groups_name groups',
              profile,
              expires_at: profile.exp || Math.floor(Date.now() / 1000) + 3600,
            }));
          } catch {}
          window.__OSP_ID_TOKEN__ = token;
          window.__OPENSPHERE_ID_TOKEN__ = token;
          window.__OS_AUTH__ = { token, groups: ${JSON.stringify(tokenGroups)}, adminGroup: ${JSON.stringify(tokenLooksAdmin)} };
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
    await waitForRuntime(client, `location.href.includes('/p/ai/cluster-settings/support-services')`, 'support-services route');
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

    await waitForRuntime(client, `(async () => {
      if (window.__oahFinalReadiness) return window.__oahFinalReadiness.ok === true;
      const res = await fetch('/api/plugins/ai/admin/native/final-readiness', { headers: { 'x-os-id-token': window.__OPENSPHERE_ID_TOKEN__ } });
      const data = await res.json().catch(() => ({}));
      window.__oahFinalReadiness = {
        ok: res.ok && data?.readinessModel?.nativeReadiness?.ready === true && !!data?.readinessModel?.parityReadiness?.evidence,
        status: res.status,
        nativeReady: data?.readinessModel?.nativeReadiness?.ready,
        parityEvidence: data?.readinessModel?.parityReadiness?.evidence || '',
        upstreamPhase: data?.upstreamPhase || ''
      };
      return window.__oahFinalReadiness.ok === true;
    })()`, 'authenticated final-readiness browser fetch');

    await waitForRuntime(client, `(async () => {
      if (window.__oahVectorAclSmoke) return window.__oahVectorAclSmoke.ok === true;
      const headers = { 'x-os-id-token': window.__OPENSPHERE_ID_TOKEN__, 'content-type': 'application/json' };
      const stateRes = await fetch('/api/plugins/ai/memory/vector?namespace=opensphere-system', { headers });
      const state = await stateRes.json().catch(() => ({}));
      const collection = (state.collections || [])[0];
      if (!stateRes.ok || !collection) {
        window.__oahVectorAclSmoke = { ok: false, stage: 'read', status: stateRes.status, error: state.error || 'no vector collection returned' };
        return false;
      }
      const originalOwner = collection.access?.owner || 'opensphere-ai-hub';
      const originalGroups = Array.from(new Set(collection.access?.groups || []));
      const smokeGroup = 'oah-live-browser-smoke';
      const nextGroups = Array.from(new Set([...originalGroups, smokeGroup]));
      const bodyBase = { namespace: collection.namespace, collection: collection.name, owner: originalOwner };
      const patchGroups = async (groups) => {
        const res = await fetch('/api/plugins/ai/memory/vector/collections', {
          method: 'PATCH',
          headers,
          body: JSON.stringify({ ...bodyBase, groups }),
        });
        return { res, data: await res.json().catch(() => ({})) };
      };
      let updateSucceeded = false;
      try {
        const { res: updateRes, data: updated } = await patchGroups(nextGroups);
        const updatedGroups = updated.collection?.access?.groups || [];
        if (!updateRes.ok || !updatedGroups.includes(smokeGroup)) {
          window.__oahVectorAclSmoke = { ok: false, stage: 'update', status: updateRes.status, error: updated.error || updated.message || 'smoke group was not applied', updatedGroups };
          return false;
        }
        updateSucceeded = true;
        const { res: restoreRes, data: restored } = await patchGroups(originalGroups);
        const restoredGroups = restored.collection?.access?.groups || [];
        window.__oahVectorAclSmoke = {
          ok: restoreRes.ok && !restoredGroups.includes(smokeGroup),
          stage: 'restore',
          status: restoreRes.status,
          collection: collection.namespace + '/' + collection.name,
          owner: originalOwner,
          originalGroups,
          restoredGroups,
          error: restoreRes.ok ? '' : (restored.error || restored.message || 'restore failed'),
        };
        return window.__oahVectorAclSmoke.ok === true;
      } catch (error) {
        window.__oahVectorAclSmoke = { ok: false, stage: 'exception', error: String(error && error.message || error) };
        return false;
      } finally {
        if (updateSucceeded && window.__oahVectorAclSmoke?.ok !== true) {
          await patchGroups(originalGroups).catch(() => undefined);
        }
      }
    })()`, 'authenticated vector owner/group browser smoke');

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
          finalReadiness: window.__oahFinalReadiness || null,
          vectorAclSmoke: window.__oahVectorAclSmoke || null,
          tokenGroups: (window.__OS_AUTH__ && window.__OS_AUTH__.groups || []).length,
          tokenAdminGroup: !!(window.__OS_AUTH__ && window.__OS_AUTH__.adminGroup),
          buttons,
        };
      })()`,
      returnByValue: true,
    });
    const value = rendered.result.result.value;
    assert(value.missing.length === 0, `Missing live rendered text: ${value.missing.join(', ')}`);
    assert(value.fetchErrors.length === 0, `Live browser fetch errors: ${value.fetchErrors.join('; ')}`);
    assert(value.tokenGroups > 0, 'Injected browser auth state has no normalized groups.');
    assert(value.finalReadiness?.ok === true, `Final readiness browser fetch failed: ${JSON.stringify(value.finalReadiness)}`);
    assert(value.vectorAclSmoke?.ok === true, `Vector owner/group browser smoke failed: ${JSON.stringify(value.vectorAclSmoke)}`);
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
