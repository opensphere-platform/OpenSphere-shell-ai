// AI — server.js. SDK 표준 subShell 피처 컨테이너: 제네릭 /api/k8s/* 프록시 + WS exec + Angular 범용콘솔(www) + subShell ui-shell 서빙.
// 셸 nginx가 /api/plugins/ai/<X> → 이 서버 /<X> 로 prefix strip 프록시.
//   /plugins/*  → 매니페스트/번들/서명
//   /app/*      → Angular dist(main.js, styles.css)
//   /api/nodes  → 노드 집계
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { WebSocketServer, WebSocket } = require('ws');
const COOKIE = 'osng_token'; // 브라우저 WS는 커스텀 헤더를 못 실음 → 신원 토큰을 HttpOnly 쿠키로 전달
function tokenFromCookie(cookieHeader) {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === COOKIE) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return null;
}
const PORT = process.env.PORT || 8080;
const PLUGINS = process.env.PLUGINS_DIR || '/app/plugins';
const WWW = process.env.WWW_DIR || '/app/www';
const VERSION = process.env.APP_VERSION || '0.1.0';
const SA = '/var/run/secrets/kubernetes.io/serviceaccount';
const APISERVER = 'https://kubernetes.default.svc';
const tok = () => fs.readFileSync(`${SA}/token`, 'utf8').trim();

// ── 쓰기 인가: 호출자 토큰을 검증 → Impersonate-User (SA 광범위 write 금지) ──
// Kanidm 콘솔 id_token(ES256) 전용 — cutover 완료, 레거시 Keycloak RS256 dual-accept 경로는 제거됨.
const { createPublicKey, verify: cryptoVerify } = require('crypto');
// Kanidm 콘솔 IdP — split-horizon: 토큰 iss는 브라우저값(localhost:8444), JWKS는 in-cluster svc.
const KANIDM_ISS = process.env.KANIDM_ISS || 'https://localhost:8444/oauth2/openid/opensphere-console';
const KANIDM_JWKS_URL = process.env.KANIDM_JWKS_URL || 'https://kanidm.opensphere-console-auth.svc:8443/oauth2/openid/opensphere-console/public_key.jwk';
const KANIDM_AZP = process.env.KANIDM_AZP || 'opensphere-console';
const KANIDM_CA_PATH = process.env.KANIDM_CA_PATH || '/etc/kanidm-ca/ca.crt';
const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
// Kanidm JWKS — 자체서명 CA를 명시적 'ca' 옵션으로 신뢰(TLS 검증 비활성화 금지, NODE_EXTRA_CA_CERTS 미접촉).
let _kjwks = null, _kjwksAt = 0;
const KJWKS_TTL = 5 * 60 * 1000;
function _kanidmGetJwks(force) {
  return new Promise((resolve, reject) => {
    if (!force && _kjwks && (Date.now() - _kjwksAt) < KJWKS_TTL) return resolve(_kjwks);
    const u = new URL(KANIDM_JWKS_URL);
    const opts = { hostname: u.hostname, port: u.port || 443, path: u.pathname + u.search, method: 'GET' };
    try { opts.ca = fs.readFileSync(KANIDM_CA_PATH); } catch (e) { console.error('[auth] kanidm CA read failed: ' + e); }
    const rq = https.request(opts, (resp) => {
      const ch = []; resp.on('data', (c) => ch.push(c));
      resp.on('end', () => { try { const j = JSON.parse(Buffer.concat(ch).toString('utf8')); _kjwks = j.keys || (j.kty ? [j] : []); _kjwksAt = Date.now(); resolve(_kjwks); } catch (e) { reject(e); } });
    });
    rq.on('error', reject); rq.end();
  });
}
const b64urlJson = (s) => JSON.parse(Buffer.from(s, 'base64url').toString('utf8'));
async function verifyToken(idToken) {
  if (!idToken) throw { code: 401, msg: 'no id token' };
  const parts = idToken.split('.');
  if (parts.length !== 3) throw { code: 401, msg: 'malformed token' };
  const header = b64urlJson(parts[0]);
  const sig = Buffer.from(parts[2], 'base64url');
  // ── Kanidm 콘솔 id_token (ES256) 전용 — alg pin (fail closed) ──
  if (header.alg !== 'ES256') throw { code: 401, msg: 'unexpected alg' };
  let jwk = (await _kanidmGetJwks()).find((k) => k.kid === header.kid);
  if (!jwk) jwk = (await _kanidmGetJwks(true)).find((k) => k.kid === header.kid); // 키 롤오버 재시도
  if (!jwk) throw { code: 401, msg: 'unknown kid (kanidm)' };
  const pub = createPublicKey({ key: jwk, format: 'jwk' });
  // ECDSA P-256: JWS 서명은 raw r||s(IEEE-P1363)이며 DER이 아님 → dsaEncoding 명시 필수.
  const ok = cryptoVerify('SHA256', Buffer.from(`${parts[0]}.${parts[1]}`), { key: pub, dsaEncoding: 'ieee-p1363' }, sig);
  if (!ok) throw { code: 401, msg: 'bad signature' };
  const c = b64urlJson(parts[1]); // 검증된 클레임
  // split-horizon: 토큰 iss는 브라우저값(localhost:8444) — 정확히 일치해야 함(JWKS는 in-cluster svc에서 받음).
  if (c.iss !== KANIDM_ISS) throw { code: 401, msg: 'bad iss' };
  const aud = Array.isArray(c.aud) ? c.aud : c.aud ? [c.aud] : [];
  if (c.azp !== KANIDM_AZP && !aud.includes(KANIDM_AZP)) throw { code: 401, msg: 'bad azp/aud' };
  // ── 공통 꼬리: 시간 검증 + 클레임 추출 ──
  const now = Date.now();
  if (c.exp && c.exp * 1000 < now) throw { code: 401, msg: 'token expired' };
  if (c.nbf && c.nbf * 1000 > now + 30000) throw { code: 401, msg: 'token not yet valid' };
  return { username: c.preferred_username || 'unknown', groups: c.groups || [] };
}
const readBody = (req) => new Promise((resolve, reject) => {
  const ch = []; req.on('data', (c) => ch.push(c)); req.on('end', () => resolve(Buffer.concat(ch))); req.on('error', reject);
});
const jsonRes = (res, code, obj) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); };

const MIME = {
  '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.json': 'application/json',
  '.html': 'text/html; charset=utf-8', '.svg': 'image/svg+xml', '.woff': 'font/woff', '.woff2': 'font/woff2',
  '.ttf': 'font/ttf', '.map': 'application/json', '.ico': 'image/x-icon',
};

async function nodes() {
  const r = await fetch(`${APISERVER}/api/v1/nodes`, { headers: { Authorization: `Bearer ${tok()}` } });
  if (!r.ok) throw new Error(`nodes HTTP ${r.status}`);
  const items = (await r.json()).items || [];
  return items.map((n) => {
    const cond = (n.status?.conditions || []).find((c) => c.type === 'Ready');
    const roles = Object.keys(n.metadata?.labels || {})
      .filter((k) => k.startsWith('node-role.kubernetes.io/'))
      .map((k) => k.split('/')[1]).filter(Boolean);
    const addr = (n.status?.addresses || []).find((a) => a.type === 'InternalIP');
    const ni = n.status?.nodeInfo || {};
    return {
      name: n.metadata?.name, ready: cond?.status === 'True',
      roles: roles.length ? roles : ['<none>'], version: ni.kubeletVersion || '',
      os: ni.osImage || '', arch: ni.architecture || '',
      cpu: n.status?.capacity?.cpu || '', memory: n.status?.capacity?.memory || '',
      internalIP: addr?.address || '', created: n.metadata?.creationTimestamp || '',
      schedulable: !n.spec?.unschedulable,
    };
  });
}

// ── 콘솔 통합 알림 연동 (ADR-UI-003 P1 발행 백본) ──
// ai 백엔드 → 콘솔 audit bus(/api/admin/events) → 셸 단일 인박스.
// 시작/노드 경고를 콘솔 인박스에 발행 = subShell이 콘솔 알림 core와 '유기적' 작동.
// best-effort: 발행 실패해도 ai 본 기능엔 영향 없음. (manifest 권한 불요 — 백엔드 in-cluster 호출)
const CONTROLLER = process.env.OSP_CONTROLLER || 'http://dupa-registry-controller.opensphere-system.svc.cluster.local:8080';
async function publishNotify(ev) {
  try {
    await fetch(`${CONTROLLER}/api/admin/events`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-opensphere-source': 'ai' },
      body: JSON.stringify({ source: 'ai', ...ev }),
    });
  } catch (e) { /* 콘솔 알림은 best-effort */ }
}
const _notifiedNodes = new Set();
async function nodeHealthPublish() {
  try {
    for (const n of await nodes()) {
      if (!n.ready && !_notifiedNodes.has(n.name)) {
        _notifiedNodes.add(n.name);
        await publishNotify({ action: 'NodeNotReady', target: `Node/${n.name}`, result: 'warning', reason: `노드 ${n.name} NotReady (ai 감지)` });
      } else if (n.ready) {
        _notifiedNodes.delete(n.name); // 복구 시 재경고 허용
      }
    }
  } catch (e) { /* best-effort */ }
}

function serveFrom(root, rel, res) {
  const fp = path.join(root, path.normalize('/' + rel).replace(/^(\.\.[/\\])+/, ''));
  if (!fp.startsWith(root)) { res.writeHead(403); return res.end('forbidden'); }
  fs.stat(fp, (err, st) => {
    if (err || !st.isFile()) { res.writeHead(404); return res.end('not found'); }
    const mime = MIME[path.extname(fp)] || 'application/octet-stream';
    // PoC: 재배포 시 셸 브라우저가 구 번들을 캐시해 변경이 안 보이는 문제 회피
    fs.createReadStream(fp).once('open', () => res.writeHead(200, { 'content-type': mime, 'cache-control': 'no-store' })).pipe(res);
  });
}

// 제네릭 K8s API 프록시: /api/k8s/<표준 K8s 경로> → APISERVER.
// 읽기(GET): SA 토큰(+토큰 있으면 사용자 임퍼소네이션). 쓰기(POST/PUT/PATCH/DELETE): 토큰 JWKS 검증 필수
// → Impersonate-User로 사용자 본인 RBAC 인가(SA 광범위 write 금지). secrets 전면 차단. 쓰기는 감사 로그.
async function k8sProxy(req, res, rawUrl) {
  // 보안: 원시 경로 정규식 매칭은 URL 인코딩(sec%72ets)으로 우회됨 → 디코드 후 세그먼트 정확 매칭.
  const qIdx = rawUrl.indexOf('?');
  const rawQuery = qIdx >= 0 ? rawUrl.slice(qIdx) : ''; // 쿼리는 원형 유지(labelSelector 등)
  let pathOnly;
  try { pathOnly = decodeURIComponent(rawUrl.slice('/api/k8s'.length).split('?')[0]); }
  catch { return jsonRes(res, 400, { error: 'bad path encoding' }); }
  if (!/^\/(api|apis)\//.test(pathOnly)) return jsonRes(res, 400, { error: 'only /api or /apis paths allowed' });
  const segs = pathOnly.split('/').filter(Boolean);
  // 이중 인코딩 거부(%xx가 디코드 후에도 남아있으면 차단)
  if (segs.some((s) => s.includes('%'))) return jsonRes(res, 400, { error: 'encoded path segments not allowed' });
  // 시크릿: 어느 세그먼트든 'secrets'면 차단(denylist)
  if (segs.includes('secrets')) return jsonRes(res, 403, { error: 'secrets are blocked by policy' });
  // 고위험 서브리소스(마지막 세그먼트) 차단: exec/attach/portforward/proxy, serviceaccounts/*/token
  const last = segs[segs.length - 1];
  if (['exec', 'attach', 'portforward', 'proxy'].includes(last)) return jsonRes(res, 403, { error: 'subresource blocked by policy' });
  if (segs.includes('serviceaccounts') && last === 'token') return jsonRes(res, 403, { error: 'token subresource blocked by policy' });

  const isWrite = WRITE_METHODS.has(req.method);
  const idToken = req.headers['x-os-id-token']; // 셸이 실어 보낸 콘솔 IdP 토큰
  // 헤더는 새로 구성 — 클라이언트의 Impersonate-*/Authorization은 절대 전달하지 않음(위조 차단)
  const headers = { Authorization: `Bearer ${tok()}`, Accept: 'application/json' };
  let actor = null;

  if (isWrite) {
    try { actor = await verifyToken(idToken); }
    catch (e) { return jsonRes(res, e.code || 401, { error: e.msg || 'unauthorized' }); }
    headers['Impersonate-User'] = actor.username;
    const ct = req.headers['content-type'];
    if (ct) headers['Content-Type'] = ct;
  } else if (idToken) {
    // 읽기: 토큰이 있으면 사용자 임퍼소네이션(per-user RBAC). 검증 실패 시 SA 읽기로 폴백.
    try { actor = await verifyToken(idToken); headers['Impersonate-User'] = actor.username; } catch { actor = null; }
  }

  const body = isWrite ? await readBody(req) : undefined;
  // 업스트림은 검증된 디코드 경로 + 원형 쿼리로 재구성(원시 sub 그대로 전달 금지)
  const r = await fetch(`${APISERVER}${pathOnly}${rawQuery}`, { method: req.method, headers, body });
  const text = await r.text();
  if (isWrite) console.log(`[audit] user=${actor && actor.username} verb=${req.method} path=${pathOnly} status=${r.status} ${new Date().toISOString()}`);
  res.writeHead(r.status, { 'content-type': r.headers.get('content-type') || 'application/json', 'cache-control': 'no-store' });
  res.end(text);
}

const server = http.createServer(async (req, res) => {
  const p = new URL(req.url, `http://${req.headers.host}`).pathname;
  try {
    if (p === '/healthz') { res.writeHead(200); return res.end('ok'); }
    if (p === '/api/session') {
      // WS(exec/터미널)용 신원 쿠키 발급 — 토큰 JWKS 검증 후 HttpOnly 쿠키로(브라우저 WS가 보낼 수 있게)
      let actor;
      try { actor = await verifyToken(req.headers['x-os-id-token']); }
      catch (e) { return jsonRes(res, e.code || 401, { error: e.msg || 'unauthorized' }); }
      const secure = req.headers['x-forwarded-proto'] === 'https' ? ' Secure;' : '';
      res.writeHead(200, {
        'content-type': 'application/json',
        'set-cookie': `${COOKIE}=${encodeURIComponent(req.headers['x-os-id-token'])}; HttpOnly; SameSite=Strict; Path=/api/plugins/ai;${secure} Max-Age=600`,
      });
      return res.end(JSON.stringify({ user: actor.username }));
    }
    if (p.startsWith('/api/k8s/')) return k8sProxy(req, res, req.url);
    if (p === '/api/nodes') {
      const list = await nodes();
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({
        meta: { service: 'ai', version: VERSION, servedBy: process.env.HOSTNAME, time: new Date().toISOString() },
        nodes: list,
      }));
    }
    if (p === '/plugins' || p === '/plugins/') {
      const files = fs.existsSync(PLUGINS) ? fs.readdirSync(PLUGINS).filter((f) => !f.startsWith('.')) : [];
      res.writeHead(200, { 'content-type': 'application/json' }); return res.end(JSON.stringify({ plugins: files }));
    }
    if (p.startsWith('/plugins/')) return serveFrom(PLUGINS, p.slice('/plugins/'.length), res);
    if (p.startsWith('/app/')) return serveFrom(WWW, p.slice('/app/'.length), res);
    res.writeHead(404); res.end('not found');
  } catch (e) {
    res.writeHead(500, { 'content-type': 'application/json' }); res.end(JSON.stringify({ error: String(e) }));
  }
});
// ── WS exec/터미널 게이트웨이 ──────────────────────────────────────────────
// 브라우저 WS(/api/k8s-exec/<ns>/<pod>?container=&command=) → 쿠키 토큰 JWKS 검증 → apiserver exec
// 채널(v4.channel.k8s.io)로 투명 릴레이. SA 토큰 + Impersonate-User로 사용자 본인 RBAC(create pods/exec) 인가.
const wss = new WebSocketServer({ noServer: true });
server.on('upgrade', async (req, socket, head) => {
  const u = new URL(req.url, 'http://x');
  const m = u.pathname.match(/^\/api\/k8s-exec\/([^/]+)\/([^/]+)$/);
  if (!m) { socket.destroy(); return; }
  let actor;
  try { actor = await verifyToken(tokenFromCookie(req.headers.cookie)); }
  catch { socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n'); socket.destroy(); return; }
  const ns = decodeURIComponent(m[1]);
  const pod = decodeURIComponent(m[2]);
  const container = u.searchParams.get('container') || '';
  const commands = u.searchParams.getAll('command');
  const cmds = commands.length ? commands : ['/bin/sh'];
  wss.handleUpgrade(req, socket, head, (browserWs) => {
    const qs = new URLSearchParams();
    if (container) qs.set('container', container);
    qs.set('stdin', 'true'); qs.set('stdout', 'true'); qs.set('stderr', 'true'); qs.set('tty', 'true');
    for (const c of cmds) qs.append('command', c);
    const upUrl = `${APISERVER.replace(/^https/, 'wss')}/api/v1/namespaces/${ns}/pods/${pod}/exec?${qs.toString()}`;
    const up = new WebSocket(upUrl, ['v4.channel.k8s.io'], {
      headers: { Authorization: `Bearer ${tok()}`, 'Impersonate-User': actor.username },
    });
    console.log(`[audit] exec user=${actor.username} pod=${ns}/${pod} container=${container} ${new Date().toISOString()}`);
    const closeBoth = () => { try { browserWs.close(); } catch {} try { up.close(); } catch {} };
    up.on('message', (data) => { if (browserWs.readyState === 1) browserWs.send(data, { binary: true }); });
    browserWs.on('message', (data) => { if (up.readyState === 1) up.send(data); });
    up.on('close', closeBoth);
    up.on('error', (e) => { try { browserWs.send(Buffer.from([3, ...Buffer.from(String(e))])); } catch {} closeBoth(); });
    browserWs.on('close', closeBoth);
    browserWs.on('error', closeBoth);
  });
});

server.listen(PORT, () => {
  console.log(`ai v${VERSION} on :${PORT}`);
  // 콘솔 인박스에 시작 이벤트 발행 + 주기적 노드 헬스(유기적 연동)
  publishNotify({ action: 'started', target: 'ai', result: 'info', reason: `AI 백엔드 v${VERSION} 시작` });
  nodeHealthPublish();
  setInterval(nodeHealthPublish, 60000);
});
