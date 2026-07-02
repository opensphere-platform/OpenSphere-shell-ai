const crypto = require('node:crypto');
const https = require('node:https');

const token = process.env.OAH_ID_TOKEN || '';
const requiredIssuer = process.env.OAH_REQUIRED_TOKEN_ISSUER || 'https://auth.console.opensphere.dev/oauth2/openid/opensphere-console';
const requiredAudience = process.env.OAH_REQUIRED_TOKEN_AUDIENCE || 'opensphere-console';
const skipSignature = /^true$/i.test(process.env.OAH_SKIP_TOKEN_SIGNATURE_VERIFY || '');
const allowUnsignedForTests = /^true$/i.test(process.env.OAH_ALLOW_UNSIGNED_ID_TOKEN_FOR_TESTS || '');
const identityGroupClaimKeys = ['groups', 'groups_name', 'group_names', 'roles'];

function fail(message, extra = {}) {
  const result = { ok: false, error: message, ...extra };
  console.error(JSON.stringify(result));
  process.exit(1);
}

function base64UrlDecode(value) {
  const padded = String(value || '').replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(String(value || '').length / 4) * 4, '=');
  return Buffer.from(padded, 'base64');
}

function decodeJsonSegment(value, label) {
  try {
    return JSON.parse(base64UrlDecode(value).toString('utf8'));
  } catch (error) {
    throw new Error(`OAH_ID_TOKEN ${label} is not valid base64url JSON: ${error.message}`);
  }
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

function httpsJson(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { timeout: 10000 }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        if (res.statusCode < 200 || res.statusCode >= 300) {
          reject(new Error(`GET ${url} returned HTTP ${res.statusCode}: ${text.slice(0, 200)}`));
          return;
        }
        try {
          resolve(JSON.parse(text));
        } catch (error) {
          reject(new Error(`GET ${url} did not return JSON: ${error.message}`));
        }
      });
    });
    req.on('timeout', () => req.destroy(new Error(`GET ${url} timed out`)));
    req.on('error', reject);
  });
}

function derLength(length) {
  if (length < 128) return Buffer.from([length]);
  const bytes = [];
  let value = length;
  while (value > 0) {
    bytes.unshift(value & 0xff);
    value >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function derInteger(raw) {
  let value = Buffer.from(raw);
  while (value.length > 1 && value[0] === 0 && (value[1] & 0x80) === 0) value = value.subarray(1);
  if (value[0] & 0x80) value = Buffer.concat([Buffer.from([0]), value]);
  return Buffer.concat([Buffer.from([0x02]), derLength(value.length), value]);
}

function joseEcdsaSignatureToDer(signature, alg) {
  const size = { ES256: 32, ES384: 48, ES512: 66 }[alg];
  if (!size) return signature;
  if (signature.length !== size * 2) throw new Error(`OAH_ID_TOKEN ${alg} signature length is ${signature.length}, expected ${size * 2}.`);
  const r = derInteger(signature.subarray(0, size));
  const s = derInteger(signature.subarray(size));
  const body = Buffer.concat([r, s]);
  return Buffer.concat([Buffer.from([0x30]), derLength(body.length), body]);
}

async function jwksUriForIssuer(issuer) {
  const discovery = await httpsJson(`${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`);
  if (!discovery.jwks_uri) throw new Error(`OIDC discovery for ${issuer} did not include jwks_uri.`);
  return discovery.jwks_uri;
}

function verifySignature({ header, signingInput, signature, jwk }) {
  const algorithms = {
    RS256: { algorithm: 'RSA-SHA256' },
    RS384: { algorithm: 'RSA-SHA384' },
    RS512: { algorithm: 'RSA-SHA512' },
    PS256: { algorithm: 'RSA-SHA256', padding: crypto.constants.RSA_PKCS1_PSS_PADDING },
    PS384: { algorithm: 'RSA-SHA384', padding: crypto.constants.RSA_PKCS1_PSS_PADDING },
    PS512: { algorithm: 'RSA-SHA512', padding: crypto.constants.RSA_PKCS1_PSS_PADDING },
    ES256: { algorithm: 'SHA256' },
    ES384: { algorithm: 'SHA384' },
    ES512: { algorithm: 'SHA512' },
  };
  const config = algorithms[header.alg];
  if (!config) throw new Error(`OAH_ID_TOKEN alg ${header.alg} is not supported by this verifier.`);
  const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const verifier = crypto.createVerify(config.algorithm);
  verifier.update(signingInput);
  verifier.end();
  const options = config.padding ? { key, padding: config.padding } : key;
  const verifySignature = header.alg.startsWith('ES') ? joseEcdsaSignatureToDer(signature, header.alg) : signature;
  if (!verifier.verify(options, verifySignature)) throw new Error('OAH_ID_TOKEN signature did not verify against issuer JWKS.');
}

async function main() {
  if (!token) fail('OAH_ID_TOKEN is not set.');
  const parts = token.split('.');
  if (parts.length < 3 || !parts[0] || !parts[1] || !parts[2]) fail('OAH_ID_TOKEN is not a signed JWT with header, payload, and signature segments.');
  const header = decodeJsonSegment(parts[0], 'header');
  const payload = decodeJsonSegment(parts[1], 'payload');
  if (!header.alg || String(header.alg).toLowerCase() === 'none') fail('OAH_ID_TOKEN must use a signed JWT alg; alg=none is not accepted.');
  if (requiredIssuer && payload.iss !== requiredIssuer) fail(`OAH_ID_TOKEN issuer mismatch: expected ${requiredIssuer}, got ${payload.iss || 'missing'}.`);
  if (requiredAudience && !claimStrings(payload.aud).includes(requiredAudience)) fail(`OAH_ID_TOKEN audience mismatch: expected ${requiredAudience}.`);
  if (payload.exp && Number(payload.exp) <= Math.floor(Date.now() / 1000)) fail('OAH_ID_TOKEN is expired.');
  const groups = identityGroupsFromPayload(payload);
  if (!groups.length) fail('OAH_ID_TOKEN does not contain any supported group claim: groups, groups_name, group_names, roles, realm_access.roles, or resource_access.*.roles.');
  if (skipSignature && !allowUnsignedForTests) {
    fail('OAH_SKIP_TOKEN_SIGNATURE_VERIFY requires OAH_ALLOW_UNSIGNED_ID_TOKEN_FOR_TESTS=true and must not be used for production verification.');
  }
  if (!skipSignature) {
    if (!header.kid) fail('OAH_ID_TOKEN header does not include kid; cannot select issuer JWKS key.');
    const jwksUri = await jwksUriForIssuer(requiredIssuer || payload.iss);
    const jwks = await httpsJson(jwksUri);
    const jwk = (jwks.keys || []).find((key) => key.kid === header.kid);
    if (!jwk) fail(`OAH_ID_TOKEN kid ${header.kid} was not found in issuer JWKS.`, { jwksUri });
    verifySignature({
      header,
      signingInput: `${parts[0]}.${parts[1]}`,
      signature: base64UrlDecode(parts[2]),
      jwk,
    });
  }
  const subject = payload.sub || payload.preferred_username || payload.email || 'unknown';
  console.log(JSON.stringify({
    ok: true,
    subject,
    issuer: payload.iss || '',
    audience: claimStrings(payload.aud),
    alg: header.alg,
    kid: header.kid || '',
    groups: groups.length,
    signatureVerified: !skipSignature,
  }));
}

main().catch((error) => fail(error.message || String(error)));
