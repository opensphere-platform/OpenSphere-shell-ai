import { createHash, createPrivateKey, sign } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const root = resolve(import.meta.dirname, '..');
const keyPath = process.env.DUPA_SIGNING_KEY;
if (!keyPath) throw new Error('DUPA_SIGNING_KEY must point to the approved P-256 signing key');
const keyId = process.env.DUPA_SIGNING_KEY_ID || 'opensphere-plugins-v1';
const hash = (value) => createHash('sha256').update(value).digest('hex');
const signature = (text, key) => sign('sha256', Buffer.from(text), { key, dsaEncoding: 'ieee-p1363' }).toString('base64');
const key = createPrivateKey(readFileSync(keyPath));

const entry = readFileSync(resolve(root, 'ui-shell/ui-shell.plugin.js'), 'utf8');
const manifestPath = resolve(root, 'ui-shell/ui-shell.manifest.json');
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
manifest.entrySha256 = hash(entry);
const manifestText = `${JSON.stringify(manifest, null, 2)}\n`;
writeFileSync(manifestPath, manifestText);
writeFileSync(resolve(root, 'ui-shell/ui-shell.manifest.json.sig'), `${signature(manifestText, key)}\n`);

const descriptor = {
  schemaVersion: 1,
  id: manifest.id,
  kind: manifest.kind,
  displayName: manifest.title,
  version: manifest.version,
  owner: 'platform-experience',
  description: manifest.description,
  hostRef: manifest.hostRef,
  hostApiVersion: manifest.hostApiVersion,
  hostCompat: manifest.hostCompat,
  shellCompat: manifest.shellCompat,
  sdkVersion: manifest.sdkVersion,
  nav: manifest.nav,
  permissions: manifest.permissions,
  permissionProfile: 'ai-domain-operator-v1',
  runtime: {
    port: 8080,
    healthPath: '/readyz',
    serviceAccountName: 'ai-runtime',
    resources: { cpuRequest: '200m', memoryRequest: '512Mi', cpuLimit: '1000m', memoryLimit: '1Gi' },
    security: {
      automountServiceAccountToken: true,
      runAsNonRoot: true,
      runAsUser: 1000,
      runAsGroup: 1000,
      readOnlyRootFilesystem: true,
      seccompProfile: 'RuntimeDefault',
    },
    availability: {
      replicas: 2,
      minAvailable: 1,
      topologySpread: true,
      autoscaling: { enabled: true, minReplicas: 2, maxReplicas: 4, targetCPUUtilization: 70 },
    },
    networkPolicy: { enabled: true, allowMonitoring: true },
    observability: {
      metricsPath: '/metrics',
      scrapeInterval: '30s',
      logs: { format: 'json', schema: 'opensphere.v1', stream: 'stdout' },
      traces: { propagation: 'w3c', responseHeaders: true },
    },
  },
  manifest: {
    path: '/plugins/ui-shell.manifest.json',
    sha256: hash(manifestText),
    signaturePath: '/plugins/ui-shell.manifest.json.sig',
  },
  trust: { keyId },
  api: { basePath: manifest.apiBase },
  contributions: manifest.contributions,
};

const sdkEntry = resolve(process.env.OPENSPHERE_SDK || resolve(root, '../OpenSphere-SDK'), 'dist/index.js');
const { validateModulePackage } = await import(pathToFileURL(sdkEntry));
const issues = validateModulePackage(descriptor);
if (issues.length) throw new Error(`OpenSphere SDK rejected module package: ${JSON.stringify(issues)}`);

const descriptorText = JSON.stringify(descriptor);
writeFileSync(resolve(root, 'module-package.json'), descriptorText);
writeFileSync(resolve(root, 'module-package.json.sig'), `${signature(descriptorText, key)}\n`);
console.log(`packaged ${descriptor.id}@${descriptor.version} manifest=${descriptor.manifest.sha256}`);
