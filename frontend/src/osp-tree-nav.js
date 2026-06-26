// ─────────────────────────────────────────────────────────────────────────
// <osp-tree-nav> — OpenSphere 표준 트리 메뉴 (단일 구현).
// 진짜 Clarity vertical-nav 마크업(.clr-vertical-nav / .nav-content / .nav-group /
// .nav-group-content / .nav-group-children / .nav-link / .nav-text)을 그대로 방출한다.
// → 셸이 전역 로드한 Clarity CSS(clr-ui.min.css)가 스타일링하므로, Angular subShell이
//   <clr-vertical-nav> 컴포넌트로 그리는 것과 시각·구조가 동일하다(근사 아님).
// 다크 테마 = cluster(K8s Console)와 동일. 최상위 항목엔 cluster처럼 leading 아이콘(인라인 SVG,
//   라벨 키워드로 자동 선택 — cds-icon 미등록 문제 없음). 기본 접힘(캐럿 >).
// API   : el.items = [{ id, label, children?: [{ id, label }] }]   ·   el.activeId = '<id>'
// Event : 'osp-nav-select'  detail:{ id }
// 프레임워크 0, ESM/<script> 모두에서 자기등록(중복 정의 가드). 각 vanilla 플러그인에 인라인.
// 색/hex/사설클래스 0 — 색은 currentColor·토큰. 동작 글루 CSS만 주입.
// ─────────────────────────────────────────────────────────────────────────
(function () {
  if (typeof window === 'undefined' || !window.customElements) return;
  if (customElements.get('osp-tree-nav')) return;

  const STYLE_ID = 'osp-tree-nav-style';
  const esc = (v) => String(v == null ? '' : v).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  // Clarity angle 대체 캐럿(우향 → 펼침 시 90° 회전).
  const CARET = '<svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true" focusable="false">' +
    '<path d="M6 4l4 4-4 4" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>';

  // ── leading 아이콘 — cluster(k8s-console-angular) nav-icons.ts 그대로 복제 ─────
  // Material 24x24 fill path. 답안지(K8s Console)와 동일 아이콘을 쓴다(직접 제작 X).
  const P = {
    dashboard: 'M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z',
    apps: 'M4 8h4V4H4v4zm0 6h4v-4H4v4zm0 6h4v-4H4v4zm6 0h4v-4h-4v4zm0-6h4v-4h-4v4zm0-10v4h4V4h-4zm6 16h4v-4h-4v4zm0-6h4v-4h-4v4zm0-10v4h4V4h-4z',
    cube: 'M21 16.5c0 .38-.21.71-.53.88l-7.9 4.44c-.16.12-.36.18-.57.18s-.41-.06-.57-.18l-7.9-4.44A.991.991 0 013 16.5v-9c0-.38.21-.71.53-.88l7.9-4.44c.16-.12.36-.18.57-.18s.41.06.57.18l7.9 4.44c.32.17.53.5.53.88v9zM12 4.15L6.04 7.5 12 10.85 17.96 7.5 12 4.15z',
    rocket: 'M12 2.5s4.5 2 4.5 9.5c0 1.9-.27 3.2-.4 3.7H7.9c-.13-.5-.4-1.8-.4-3.7C7.5 4.5 12 2.5 12 2.5zm0 6a1.5 1.5 0 100 3 1.5 1.5 0 000-3zM8 17h8l-1.5 4-1-1.5h-3L9.5 21 8 17z',
    layers: 'M11.99 18.54l-7.37-5.73L3 14.07l9 7 9-7-1.63-1.27-7.38 5.74zM12 16l7.36-5.73L21 9l-9-7-9 7 1.63 1.27L12 16z',
    clock: 'M12 2a10 10 0 100 20 10 10 0 000-20zm0 18a8 8 0 110-16 8 8 0 010 16zm.5-13H11v6l5.25 3.15.75-1.23-4.5-2.67V7z',
    task: 'M19 3h-4.18C14.4 1.84 13.3 1 12 1s-2.4.84-2.82 2H5a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2V5a2 2 0 00-2-2zm-7 0a1 1 0 110 2 1 1 0 010-2zm-2 14l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z',
    trending: 'M16 6l2.29 2.29-4.88 4.88-4-4L2 16.59 3.41 18l6-6 4 4 6.3-6.29L22 12V6z',
    shield: 'M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z',
    share: 'M18 16.08c-.76 0-1.44.3-1.96.77L8.91 12.7c.05-.23.09-.46.09-.7s-.04-.47-.09-.7l7.05-4.11c.54.5 1.25.81 2.04.81 1.66 0 3-1.34 3-3s-1.34-3-3-3-3 1.34-3 3c0 .24.04.47.09.7L8.04 9.81C7.5 9.31 6.79 9 6 9c-1.66 0-3 1.34-3 3s1.34 3 3 3c.79 0 1.5-.31 2.04-.81l7.12 4.16c-.05.21-.08.43-.08.65 0 1.61 1.31 2.92 2.92 2.92s2.92-1.31 2.92-2.92-1.31-2.92-2.92-2.92z',
    input: 'M11 7L9.6 8.4l2.6 2.6H2v2h10.2l-2.6 2.6L11 17l5-5-5-5zm9 12h-8v2h8a2 2 0 002-2V5a2 2 0 00-2-2h-8v2h8v14z',
    link: 'M3.9 12a3.1 3.1 0 013.1-3.1h4V7H7a5 5 0 000 10h4v-1.9H7A3.1 3.1 0 013.9 12zM8 13h8v-2H8v2zm9-6h-4v1.9h4a3.1 3.1 0 010 6.2h-4V17h4a5 5 0 000-10z',
    lock: 'M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V10a2 2 0 00-2-2zm-6 9a2 2 0 110-4 2 2 0 010 4zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z',
    settings: 'M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58a.49.49 0 00.12-.61l-1.92-3.32a.49.49 0 00-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54a.484.484 0 00-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96a.48.48 0 00-.59.22L2.74 8.87a.49.49 0 00.12.61l2.03 1.58c-.05.3-.07.62-.07.94s.02.64.07.94l-2.03 1.58a.49.49 0 00-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32a.49.49 0 00-.12-.61l-2.01-1.58zM12 15.6a3.6 3.6 0 110-7.2 3.6 3.6 0 010 7.2z',
    gauge: 'M12 4a8 8 0 00-8 8 8 8 0 001.69 4.9l1.43-1.43A6 6 0 1118 12h2a8 8 0 00-8-8zm0 14a2 2 0 002-2c0-.55-.22-1.05-.59-1.41L12 11l-1.41 5.59c-.37.36-.59.86-.59 1.41a2 2 0 002 2z',
    disk: 'M12 2a10 10 0 100 20 10 10 0 000-20zm0 13a3 3 0 110-6 3 3 0 010 6z',
    storage: 'M2 20h20v-4H2v4zm2-3h2v2H4v-2zM2 4v4h20V4H2zm4 3H4V5h2v2zm-4 7h20v-4H2v4zm2-3h2v2H4v-2z',
    server: 'M20 13H4c-.55 0-1 .45-1 1v6c0 .55.45 1 1 1h16c.55 0 1-.45 1-1v-6c0-.55-.45-1-1-1zM7 19c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm13-15H4c-.55 0-1 .45-1 1v6c0 .55.45 1 1 1h16c.55 0 1-.45 1-1V5c0-.55-.45-1-1-1zM7 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z',
    folder: 'M10 4H4a2 2 0 00-2 2v12a2 2 0 002 2h16a2 2 0 002-2V8a2 2 0 00-2-2h-8l-2-2z',
    flag: 'M14.4 6L14 4H5v17h2v-7h5.6l.4 2h7V6z',
    bell: 'M12 22a2 2 0 002-2h-4a2 2 0 002 2zm6-6v-5c0-3.07-1.63-5.64-4.5-6.32V4a1.5 1.5 0 00-3 0v.68C7.64 5.36 6 7.92 6 11v5l-2 2v1h16v-1l-2-2z',
    schema: 'M22 11V3h-7v3H9V3H2v8h7V8h2v10h4v3h7v-8h-7v3h-2V8h2v3z',
    person: 'M12 12a5 5 0 100-10 5 5 0 000 10zm0 2c-3.33 0-10 1.67-10 5v3h20v-3c0-3.33-6.67-5-10-5z',
    key: 'M12.65 10A6 6 0 105.5 16a6 6 0 005.65-4H15v3h3v-3h2v-3h-7.35zM7 14a2 2 0 110-4 2 2 0 010 4z',
    doc: 'M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z',
  };
  // cluster app.component.ts와 동일: <svg class="os-tree-ic" viewBox="0 0 24 24"><path d=.../></svg> (자식=os-tree-ic-child)
  const ICON_SVG = (d, child) => '<svg class="os-tree-ic' + (child ? ' os-tree-ic-child' : '') +
    '" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" focusable="false"><path d="' + d + '"/></svg>';
  // 라벨 키워드 → cluster 아이콘 키. 매칭 없으면 그룹=folder / 리프=doc(=cluster fallback).
  const ICON_RULES = [
    [/개요|overview|대시|dashboard|^home$/i, 'dashboard'],
    [/클러스터|cluster|fleet|플릿|placement|workload/i, 'apps'],
    [/노드|node|머신|machine|컴퓨트|compute|\bcpu\b|machineconfig|mcd|mco|서버|server/i, 'server'],
    [/클라우드|cloud|리전|region|가용|schema|토폴로지/i, 'schema'],
    [/인증|auth|keycloak|보안|security|\brbac\b|패스키|\bmfa\b|realm|페더|federation|shield/i, 'shield'],
    [/권한|인가|토큰|token|\bsso\b|\bidp\b|\brole\b|역할|\bkey\b/i, 'key'],
    [/사원|사용자|user|계정|account|serviceaccount|person/i, 'person'],
    [/그룹|group|조직|부서|\borg\b|rolebinding|동기화|sync|scim|iga|link/i, 'link'],
    [/네트워크|network|ingress|route|\btls\b|netpol|웹사이트|website|directus|service|share/i, 'share'],
    [/스토리지|storage|볼륨|volume|ceph|disk|디스크/i, 'storage'],
    [/데이터셋|dataset|데이터|\bdata\b|\bdb\b|database|backup|백업|postgres|pvc|pv\b/i, 'disk'],
    [/에이전트|agent|\bllm\b|추론|inference|foundation ai|retrieval|검색|cube/i, 'cube'],
    [/학습|training|파인튜닝|tuning|임베딩|embedding|모델|model|승급|layers/i, 'layers'],
    [/평가|eval|가드|guard|정책|policy|감사|audit|task|잡\b|job/i, 'task'],
    [/세션|session|로그인|시간|time|clock|로그|log/i, 'clock'],
    [/운영|\bops\b|모니터링|monitoring|observability|gauge|쿼터|quota|limit/i, 'gauge'],
    [/관리|manage|maintenance|상태|status|settings|설정|configmap|config/i, 'settings'],
    [/카탈로그|catalog|마켓|market|애드온|addon|offering/i, 'apps'],
    [/배포|deploy|deployment|rocket|승격/i, 'rocket'],
    [/\bapi\b|개발|develop|코드|code|operator|helm|provision|위저드|wizard|input/i, 'input'],
    [/추세|trend|hpa|vpa|스케일|scale/i, 'trending'],
    [/이벤트|event|알림|bell|notice|공지/i, 'bell'],
    [/네임스페이스|namespace|폴더|folder/i, 'folder'],
    [/정책 클래스|priorityclass|flag|플래그/i, 'flag'],
    [/문서|\bdoc|가이드|guide|튜토리얼|tutorial|페이지|page/i, 'doc'],
  ];
  function iconFor(label, isGroup, child) {
    const L = String(label || '');
    for (let i = 0; i < ICON_RULES.length; i++) { if (ICON_RULES[i][0].test(L)) return ICON_SVG(P[ICON_RULES[i][1]], child); }
    return ICON_SVG(isGroup ? P.folder : P.doc, child);
  }

  // 다크 테마 = cluster와 동일(각 nav 요소에 인라인으로 박아 전역 라이트 토큰을 덮음).
  const THEME = {
    '--clr-vertical-nav-bg-color': 'var(--os-nav-bg, #101a38)',
    '--clr-vertical-nav-item-color': 'var(--os-nav-item, #c7d0e8)',
    '--clr-vertical-nav-item-active-color': 'var(--os-nav-item-active, #fff)',
    '--clr-vertical-nav-item-active-bg-color': 'var(--os-nav-active-bg, rgba(76,111,255,.22))',
    '--clr-vertical-nav-selected-bg-color': 'var(--os-nav-active-bg, rgba(76,111,255,.22))',
    '--clr-vertical-nav-hover-bg-color': 'var(--os-nav-hover-bg, rgba(255,255,255,.06))',
  };

  function ensureStyle() {
    if (document.getElementById(STYLE_ID)) return;
    const s = document.createElement('style');
    s.id = STYLE_ID;
    s.textContent = [
      'osp-tree-nav{display:block;height:100%;overflow-y:auto}',
      'osp-tree-nav .clr-vertical-nav{height:100%}',
      // leading 아이콘 (cluster 스타일)
      'osp-tree-nav .nav-link{display:flex;align-items:center}',
      // cluster app.component.css 그대로 — os-brand 헤더 + os-tree-ic 아이콘 + 자식패널 투명 + active override
      'osp-tree-nav .os-brand{padding:10px 16px 12px;font-size:.95rem;font-weight:500;' +
        'color:var(--os-nav-item-active,#fff);background:var(--os-nav-bg,#101a38)}',
      'osp-tree-nav .os-tree-ic{width:16px;height:16px;fill:currentColor;flex:0 0 auto;opacity:.85;margin-right:.55rem}',
      'osp-tree-nav .os-tree-ic-child{width:14px;height:14px}',
      'osp-tree-nav .nav-group-children,osp-tree-nav .nav-group-content{background:transparent}',
      'osp-tree-nav .nav-link.active{color:var(--os-nav-item-active,#fff);' +
        'background:var(--os-nav-active-bg,rgba(76,111,255,.22))}',
      // 그룹 펼침/접힘
      'osp-tree-nav .nav-group>.nav-group-children{display:block}',
      'osp-tree-nav .nav-group:not(.is-expanded)>.nav-group-children{display:none}',
      // 캐럿: 그룹 헤더 우측, 펼침 시 회전
      'osp-tree-nav .nav-group>.nav-group-content{position:relative}',
      'osp-tree-nav .nav-group>.nav-group-content>.nav-link{padding-right:2rem}',
      'osp-tree-nav .nav-group-trigger{position:absolute;top:0;right:0;height:100%;display:flex;align-items:center;' +
        'background:transparent;border:0;padding:0 .6rem;cursor:pointer;color:inherit}',
      'osp-tree-nav .nav-group-trigger-icon{display:inline-flex;align-items:center;transition:transform .2s ease-in-out}',
      'osp-tree-nav .nav-group.is-expanded>.nav-group-content .nav-group-trigger-icon{transform:rotate(90deg)}',
    ].join('');
    (document.head || document.documentElement).appendChild(s);
  }

  class OspTreeNav extends HTMLElement {
    constructor() {
      super();
      this._items = [];
      this._active = null;
      this._open = new Set();
      this._seeded = false;
      this._brand = '';
    }

    set brand(v) { this._brand = v == null ? '' : String(v); this._render(); }
    get brand() { return this._brand; }

    set items(v) {
      this._items = Array.isArray(v) ? v : [];
      if (!this._seeded) { this._seeded = true; this._openActive(); } // 기본 접힘(>) — 활성 항목이 속한 그룹만 펼침
      this._render();
    }
    get items() { return this._items; }

    set activeId(id) { this._active = id; this._openActive(); this._render(); }
    get activeId() { return this._active; }

    // 활성 페이지가 속한 그룹은 열어 둔다(나머지는 접힘 → 캐럿 > 표시). Foundation/ai/cluster 기본 동작과 일치.
    _openActive() {
      if (this._active == null) return;
      for (const n of this._items) {
        if (n.children && n.children.some((c) => c.id === this._active)) this._open.add(n.id);
      }
    }

    connectedCallback() { ensureStyle(); if (!this._brand) this._brand = this.getAttribute('brand') || ''; this._render(); }

    _select(id) {
      this._active = id;
      this.dispatchEvent(new CustomEvent('osp-nav-select', { detail: { id }, bubbles: true }));
      this._render();
    }
    _toggle(id) { this._open.has(id) ? this._open.delete(id) : this._open.add(id); this._render(); }

    // cluster app.component.ts처럼 모든 항목에 os-tree-ic 아이콘(자식=os-tree-ic-child).
    _linkHtml(n, child) {
      const active = this._active === n.id ? ' active' : '';
      return '<a class="nav-link' + active + '" href="javascript:void(0)" data-sel="' + esc(n.id) + '">' +
        iconFor(n.label, false, child) +
        '<span class="nav-text">' + esc(n.label) + '</span></a>';
    }
    _groupHtml(n) {
      const open = this._open.has(n.id);
      const kids = (n.children || []).map((c) => this._linkHtml(c, true)).join('');
      return '<div class="nav-group' + (open ? ' is-expanded' : '') + '">' +
        '<div class="nav-group-content">' +
          '<a class="nav-link" href="javascript:void(0)" data-grp="' + esc(n.id) + '">' +
            iconFor(n.label, true, false) +
            '<span class="nav-text">' + esc(n.label) + '</span></a>' +
          '<button class="nav-group-trigger" type="button" data-grp="' + esc(n.id) + '" ' +
            'aria-expanded="' + open + '" aria-label="' + esc(n.label) + ' 펼치기/접기">' +
            '<span class="nav-group-trigger-icon">' + CARET + '</span></button>' +
        '</div>' +
        '<div class="nav-group-children">' + kids + '</div>' +
      '</div>';
    }
    _render() {
      const body = this._items
        .map((n) => (n.children && n.children.length) ? this._groupHtml(n) : this._linkHtml(n, false))
        .join('');
      const brand = this._brand ? '<div class="os-brand">' + esc(this._brand) + '</div>' : '';
      this.innerHTML = '<div class="clr-vertical-nav">' + brand + '<div class="nav-content">' + body + '</div></div>';
      const root = this.firstElementChild; // .clr-vertical-nav — 테마 토큰 인라인 적용(전역 라이트 덮기)
      if (root) for (const k in THEME) root.style.setProperty(k, THEME[k]);
      this.querySelectorAll('[data-sel]').forEach((el) =>
        el.addEventListener('click', () => this._select(el.getAttribute('data-sel'))));
      this.querySelectorAll('[data-grp]').forEach((el) =>
        el.addEventListener('click', () => this._toggle(el.getAttribute('data-grp'))));
    }
  }

  customElements.define('osp-tree-nav', OspTreeNav);
})();
