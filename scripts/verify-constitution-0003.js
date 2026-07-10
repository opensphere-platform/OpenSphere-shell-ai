const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const yaml = require('js-yaml');

const root = path.resolve(__dirname, '..');
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'ui-shell', 'ui-shell.manifest.json'), 'utf8'));
const resources = yaml.loadAll(fs.readFileSync(path.join(root, 'uipluginpackage.yaml'), 'utf8'));
const pkg = resources.find((item) => item?.kind === 'UIPluginPackage');
const registration = resources.find((item) => item?.kind === 'UIPluginRegistration');
const adapter = fs.readFileSync(path.join(root, 'ui-shell', 'ui-shell.plugin.js'), 'utf8');
const server = fs.readFileSync(path.join(root, 'server.js'), 'utf8');
const rbac = fs.readFileSync(path.join(root, 'rbac.yaml'), 'utf8');

assert.equal(manifest.kind, 'subShell');
assert.equal(manifest.hostRef, 'main');
assert.equal(manifest.hostApiVersion, '1.0.0');
assert.equal(pkg.spec.kind, 'subShell');
assert.equal(pkg.spec.hostRef, 'main');
assert.equal(registration.spec.desiredState, 'Enabled');

const requiredCapabilities = [
  'page:register', 'api:proxy', 'nav:contribute', 'search:contribute', 'notify:publish',
];
for (const capability of requiredCapabilities) {
  assert.ok(manifest.permissions.includes(capability), `manifest capability missing: ${capability}`);
  assert.ok(pkg.spec.permissions.includes(capability), `package capability missing: ${capability}`);
}

for (const name of ['page', 'navigation', 'api', 'cli', 'manual', 'search', 'notification', 'observability']) {
  assert.equal(manifest.contributions[name].enabled, true, `manifest contribution disabled: ${name}`);
  assert.equal(pkg.spec.contributions[name].enabled, true, `package contribution disabled: ${name}`);
}
assert.equal(pkg.spec.cli.namespace, 'ai');
assert.equal(pkg.spec.cli.manifestPath, '/admin/native/agent-tools');
assert.equal(pkg.spec.contributions.manual.mode, 'install-time');
assert.equal(pkg.spec.contributions.manual.sourceId, 'plugin:ai');
assert.deepEqual(pkg.spec.contributions.notification, { enabled: true, frontend: true, backend: true });
assert.deepEqual(pkg.spec.contributions.observability, { enabled: true, logs: true, metrics: true, traces: true });

for (const marker of [
  'ctx.routing', 'extensions.nav?.contribute', 'extensions.search?.contribute',
  'ctx.notify?.publish', 'export function deactivate',
]) assert.match(adapter, new RegExp(marker.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

for (const endpoint of [
  "p === '/readyz'", "p === '/openapi.json'", "p === '/search'",
  "p === '/manual/source'", "p === '/operations/ledger'",
  "p === '/admin/native/agent-tools'", "p === '/metrics'",
]) assert.ok(server.includes(endpoint), `backend endpoint missing: ${endpoint}`);

for (const contract of [
  'X-OS-Correlation-ID is required', 'X-OS-Idempotency-Key is required',
  "event: 'http_request'", 'durable audit unavailable',
  'opensphere-auth.opensphere-console-auth.svc',
]) assert.ok(server.includes(contract), `backend contract missing: ${contract}`);

assert.match(rbac, /name:\s*ai-runtime/);
assert.match(rbac, /name:\s*ai-runtime[\s\S]*name:\s*ai-reader/);
assert.match(rbac, /name:\s*ai-runtime[\s\S]*name:\s*ai-controller/);
console.log('CONSTITUTION-0003 AI Production subShell contract: PASS');
