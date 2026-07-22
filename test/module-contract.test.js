'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash, createPublicKey, verify } = require('node:crypto');
const yaml = require('js-yaml');

const root = path.resolve(__dirname, '..');
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'ui-shell', 'ui-shell.manifest.json'), 'utf8'));
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

test('declares the canonical Main Shell identity and API surface', () => {
  assert.equal(manifest.id, 'ai');
  assert.equal(manifest.kind, 'subShell');
  assert.equal(manifest.hostRef, 'main');
  assert.equal(manifest.apiBase, '/api/plugins/ai');
  assert.equal(manifest.contributions.cli.namespace, 'ai');
  assert.equal(manifest.contributions.cli.manifestPath, '/admin/native/agent-tools');
  assert.deepEqual(manifest.permissions, [
    'page:register', 'api:proxy', 'nav:contribute', 'search:contribute',
    'manual:contribute', 'notify:publish',
  ]);
});

test('implements every production integration contribution', () => {
  for (const name of ['page', 'navigation', 'api', 'cli', 'manual', 'search', 'notification', 'observability']) {
    assert.equal(manifest.contributions[name].enabled, true, `${name} must be implemented`);
  }
  assert.equal(manifest.contributions.manual.sourceId, 'opensphere-ai-hub');
  assert.equal(manifest.contributions.manual.mode, 'runtime');
  assert.deepEqual(
    [manifest.contributions.observability.logs, manifest.contributions.observability.metrics, manifest.contributions.observability.traces],
    [true, true, true],
  );
});

test('ships actual navigation, search, manual and notification implementations', () => {
  const entry = fs.readFileSync(path.join(root, 'ui-shell', 'ui-shell.plugin.js'), 'utf8');
  const manual = fs.readFileSync(path.join(root, 'ui-shell', 'manual', 'ai.ko.md'), 'utf8');
  assert.match(entry, /extensions\.nav\?\.contribute/);
  assert.match(entry, /extensions\.search\?\.contribute/);
  assert.match(entry, /extensions\.manual\.contribute/);
  assert.match(entry, /notify\?\.publish/);
  assert.match(entry, /extensions\.manual\?\.clear/);
  assert.match(manual, /OpenSphere AI Hub/);
  assert.match(manual, /os ai readiness/);
  assert.match(manual, /opensphere\.v1/);
});

test('declares the standard runtime observability and status endpoints', () => {
  const server = fs.readFileSync(path.join(root, 'server.js'), 'utf8');
  for (const route of ['/healthz', '/readyz', '/metrics', '/api/info', '/api/status', '/api/contract', '/openapi.json']) {
    assert.ok(server.includes(`'${route}'`), `missing route ${route}`);
  }
  for (const field of [
    'schema: LOG_SCHEMA', 'resourceKind:', 'resourceName:', 'correlationId:',
    'operationId:', 'traceId:', 'actorType:', 'durationMs:',
  ]) assert.ok(server.includes(field), `missing structured log field ${field}`);
  assert.match(server, /opensphere_subshell_http_requests_total/);
  assert.match(server, /opensphere_subshell_ready/);
});

test('keeps the signed manifest and legacy package pin internally consistent', () => {
  const entry = fs.readFileSync(path.join(root, 'ui-shell', 'ui-shell.plugin.js'));
  const manifestBytes = fs.readFileSync(path.join(root, 'ui-shell', 'ui-shell.manifest.json'));
  const signature = fs.readFileSync(path.join(root, 'ui-shell', 'ui-shell.manifest.json.sig'), 'utf8').trim();
  const resources = yaml.loadAll(fs.readFileSync(path.join(root, 'uipluginpackage.yaml'), 'utf8'));
  const pkg = resources.find((item) => item?.kind === 'UIPluginPackage');
  assert.equal(manifest.entrySha256, sha256(entry));
  assert.equal(pkg.spec.manifest.sha256, sha256(manifestBytes));
  assert.equal(pkg.spec.version, manifest.version);
  assert.match(signature, /^[A-Za-z0-9+/]{86}==$/);
});

test('publishes a signed OCI module descriptor for the AI domain operator profile', () => {
  const descriptorText = fs.readFileSync(path.join(root, 'module-package.json'), 'utf8');
  const descriptor = JSON.parse(descriptorText);
  const signature = fs.readFileSync(path.join(root, 'module-package.json.sig'), 'utf8').trim();
  const key = createPublicKey({
    key: Buffer.from('MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEez09mUpKxAetbTqqktGZJ9MObsK2jFXM+Q8xM1invyK7oMlB2gwHZUtKBFcrev6AK4bWHRHhhoAJz7ukuH/6cA==', 'base64'),
    format: 'der', type: 'spki',
  });
  assert.equal(descriptor.id, 'ai');
  assert.equal(descriptor.permissionProfile, 'ai-domain-operator-v1');
  assert.equal(descriptor.runtime.healthPath, '/readyz');
  assert.equal(descriptor.runtime.security.automountServiceAccountToken, true);
  assert.equal(descriptor.manifest.sha256, sha256(fs.readFileSync(path.join(root, 'ui-shell', 'ui-shell.manifest.json'))));
  assert.equal(verify('sha256', Buffer.from(descriptorText), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(signature, 'base64')), true);
});
