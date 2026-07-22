'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const path = require('node:path');
const { spawn } = require('node:child_process');

async function availablePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close((error) => error ? reject(error) : resolve(port));
    });
  });
}

async function waitFor(url, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  let last;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.ok) return response;
      last = new Error(`HTTP ${response.status}`);
    } catch (error) { last = error; }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw last || new Error(`timeout waiting for ${url}`);
}

async function waitForStatus(url, expectedStatus, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  let last;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.status === expectedStatus) return response;
      last = new Error(`HTTP ${response.status}`);
    } catch (error) { last = error; }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw last || new Error(`timeout waiting for HTTP ${expectedStatus}`);
}

test('serves the standard runtime contract with correlation and metrics', async (t) => {
  const port = await availablePort();
  const root = path.resolve(__dirname, '..');
  const child = spawn(process.execPath, ['server.js'], {
    cwd: root,
    env: {
      ...process.env,
      PORT: String(port),
      APP_VERSION: '1.1.0-edge.1',
      PLUGINS_DIR: path.join(root, 'ui-shell'),
      WWW_DIR: path.join(root, 'dist', 'ai', 'browser'),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const stdout = [];
  const stderr = [];
  child.stdout.on('data', (chunk) => stdout.push(String(chunk)));
  child.stderr.on('data', (chunk) => stderr.push(String(chunk)));
  t.after(() => { if (!child.killed) child.kill(); });

  await waitFor(`http://127.0.0.1:${port}/healthz`);
  const status = await fetch(`http://127.0.0.1:${port}/api/status`, {
    headers: {
      'x-os-correlation-id': 'ai-contract-test',
      'x-os-operation-id': 'status-read',
      traceparent: '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01',
    },
  });
  assert.equal(status.status, 200);
  assert.equal(status.headers.get('x-os-correlation-id'), 'ai-contract-test');
  assert.equal(status.headers.get('x-os-operation-id'), 'status-read');
  assert.equal(status.headers.get('x-os-trace-id'), '0123456789abcdef0123456789abcdef');
  const body = await status.json();
  assert.equal(body.ready, true);
  assert.equal(body.integrations.manual, 'Ready');
  assert.equal(body.integrations.logs, 'Ready');

  const contract = await fetch(`http://127.0.0.1:${port}/api/contract`);
  assert.equal(contract.status, 200);
  assert.equal((await contract.json()).observability.logs.schema, 'opensphere.v1');

  const manual = await fetch(`http://127.0.0.1:${port}/plugins/manual/ai.ko.md`);
  assert.equal(manual.status, 200);
  assert.match(manual.headers.get('content-type'), /text\/markdown/);
  assert.match(await manual.text(), /OpenSphere AI Hub/);

  const metrics = await fetch(`http://127.0.0.1:${port}/metrics`);
  const exposition = await metrics.text();
  assert.match(exposition, /opensphere_subshell_http_requests_total/);
  assert.match(exposition, /opensphere_subshell_ready\{service="ai",version="1\.1\.0-edge\.1"\} 1/);

  await new Promise((resolve) => setTimeout(resolve, 100));
  const records = stdout.join('').split(/\r?\n/).filter((line) => line.startsWith('{')).map((line) => JSON.parse(line));
  const request = records.find((record) => record.correlationId === 'ai-contract-test');
  assert.ok(request, `structured request log missing; stderr=${stderr.join('')}`);
  assert.equal(request.schema, 'opensphere.v1');
  assert.equal(request.operationId, 'status-read');
  assert.equal(request.traceId, '0123456789abcdef0123456789abcdef');
  assert.equal(request.resourceKind, 'HTTPRoute');
});

test('managed OCI runtime fails readiness when cluster prerequisites are absent', async (t) => {
  const port = await availablePort();
  const root = path.resolve(__dirname, '..');
  const child = spawn(process.execPath, ['server.js'], {
    cwd: root,
    env: {
      ...process.env,
      PORT: String(port),
      OSP_AI_RUNTIME_MODE: 'managed',
      AI_DOMAIN_NAMESPACE: 'opensphere-system',
      WORKBENCH_IMAGE: `ghcr.io/opensphere-platform/opensphere-ai-workbench@sha256:${'a'.repeat(64)}`,
      PLUGINS_DIR: path.join(root, 'ui-shell'),
      WWW_DIR: path.join(root, 'dist', 'ai', 'browser'),
    },
    stdio: ['ignore', 'ignore', 'ignore'],
  });
  t.after(() => { if (!child.killed) child.kill(); });
  const response = await waitForStatus(`http://127.0.0.1:${port}/readyz`, 503);
  const body = await response.json();
  assert.equal(body.ready, false);
  assert.ok(body.checks.some((check) => check.name === 'serviceAccountToken' && check.ready === false));
});
