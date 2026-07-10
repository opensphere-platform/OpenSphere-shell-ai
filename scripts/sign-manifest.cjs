const fs = require('node:fs');
const path = require('node:path');
const { createHash, createPrivateKey, createPublicKey, sign } = require('node:crypto');

const root = path.resolve(__dirname, '..');
const keyPath = process.env.DUPA_SIGNING_KEY || path.resolve(root, '..', '..', 'dupa-signing-key.pem');
const expectedSpki = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEez09mUpKxAetbTqqktGZJ9MObsK2jFXM+Q8xM1invyK7oMlB2gwHZUtKBFcrev6AK4bWHRHhhoAJz7ukuH/6cA==';
const entryPath = path.join(root, 'ui-shell', 'ui-shell.plugin.js');
const manifestPath = path.join(root, 'ui-shell', 'ui-shell.manifest.json');
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

const key = createPrivateKey(fs.readFileSync(keyPath));
const actualSpki = createPublicKey(key).export({ type: 'spki', format: 'der' }).toString('base64');
if (actualSpki !== expectedSpki) throw new Error('signing key does not match opensphere-plugins-v1 trust root');

const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
manifest.entrySha256 = sha256(fs.readFileSync(entryPath));
const manifestText = `${JSON.stringify(manifest, null, 2)}\n`;
fs.writeFileSync(manifestPath, manifestText);
fs.writeFileSync(`${manifestPath}.sig`, `${sign('sha256', Buffer.from(manifestText), { key, dsaEncoding: 'ieee-p1363' }).toString('base64')}\n`);
console.log(JSON.stringify({ entrySha256: manifest.entrySha256, manifestSha256: sha256(Buffer.from(manifestText)), keyId: 'opensphere-plugins-v1' }));
