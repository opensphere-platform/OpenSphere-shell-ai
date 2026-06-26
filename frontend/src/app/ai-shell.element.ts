import { Component, OnInit, signal, computed } from '@angular/core';
import { ClarityModule } from '@clr/angular';
import { NAV_ICON } from './nav-icons';

// ---------------------------------------------------------------------------
// Page / Nav types
// ---------------------------------------------------------------------------
type PageId =
  | 'home'
  | 'llm-routes'
  | 'retrieval'
  | 'agents'
  | 'compute'
  | 'datasets'
  | 'training-jobs'
  | 'model-promotion'
  | 'eval-policy'
  | 'eval-jobs'
  | 'inference'
  | 'monitoring'
  | 'catalog';

// Legacy alias map: old PageIds kept for internal resource fetches
type LegacyPageId =
  | 'home'
  | 'foundation'
  | 'agents'
  | 'training'
  | 'models'
  | 'evaluation'
  | 'inference'
  | 'monitoring'
  | 'catalog';

// ---------------------------------------------------------------------------
// Nav structure
// ---------------------------------------------------------------------------
interface NavLeaf {
  kind: 'leaf';
  id: PageId;
  label: string;
}

interface NavGroup {
  kind: 'group';
  id: string;
  label: string;
  children: NavLeaf[];
}

type NavNode = NavLeaf | NavGroup;

// ---------------------------------------------------------------------------
// API response interfaces
// ---------------------------------------------------------------------------
interface Capability {
  name: string;
  plane: string;
  ready: boolean;
  phase: string;
}

interface SummaryResponse {
  ready: boolean;
  phase: string;
  capabilities: Capability[];
  counts: {
    llmRoutes: number;
    agents: number;
    trainingJobs: number;
    evaluationJobs: number;
    inferenceEndpoints: number;
  };
  alerts: Array<{ severity: string; message: string }>;
}

interface ResourceItem {
  name: string;
  kind: string;
  phase: string;
  ready: boolean;
}

interface ResourceListResponse {
  items: ResourceItem[];
}

// ---------------------------------------------------------------------------
// Nav definition
// ---------------------------------------------------------------------------
const NAV_NODES: NavNode[] = [
  { kind: 'leaf', id: 'home', label: '개요' },
  {
    kind: 'group', id: 'g-foundation', label: 'Foundation AI',
    children: [
      { kind: 'leaf', id: 'llm-routes', label: 'LLM 라우트' },
      { kind: 'leaf', id: 'retrieval',  label: '검색(retrieval)' },
    ],
  },
  {
    kind: 'group', id: 'g-agents', label: '에이전트',
    children: [
      { kind: 'leaf', id: 'agents', label: '에이전트' },
    ],
  },
  {
    kind: 'group', id: 'g-training', label: '학습·모델',
    children: [
      { kind: 'leaf', id: 'compute',         label: '컴퓨트' },
      { kind: 'leaf', id: 'datasets',        label: '데이터셋' },
      { kind: 'leaf', id: 'training-jobs',   label: '학습 잡' },
      { kind: 'leaf', id: 'model-promotion', label: '모델 승급' },
    ],
  },
  {
    kind: 'group', id: 'g-eval', label: '평가·추론',
    children: [
      { kind: 'leaf', id: 'eval-policy', label: '평가 정책' },
      { kind: 'leaf', id: 'eval-jobs',   label: '평가 잡' },
      { kind: 'leaf', id: 'inference',   label: '추론' },
    ],
  },
  {
    kind: 'group', id: 'g-ops', label: '운영',
    children: [
      { kind: 'leaf', id: 'monitoring', label: '모니터링' },
      { kind: 'leaf', id: 'catalog',    label: '카탈로그' },
    ],
  },
];

// PageId → API path segment
const RESOURCE_PATH: Partial<Record<PageId, string>> = {
  'llm-routes':      'foundation/routes',
  'retrieval':       'foundation/routes',   // reuse until dedicated endpoint
  'agents':          'resources/agents',
  'compute':         'training/jobs',       // placeholder
  'datasets':        'training/jobs',       // placeholder
  'training-jobs':   'training/jobs',
  'model-promotion': 'models/promotions',
  'eval-policy':     'evaluation/jobs',     // placeholder
  'eval-jobs':       'evaluation/jobs',
  'inference':       'inference',
  'monitoring':      'inference',           // no dedicated monitoring endpoint
  'catalog':         'catalog',
};

// PageId → display label for the resource page header
const PAGE_LABEL: Partial<Record<PageId, string>> = {
  'llm-routes':      'LLM 라우트',
  'retrieval':       '검색(retrieval)',
  'agents':          '에이전트',
  'compute':         '컴퓨트',
  'datasets':        '데이터셋',
  'training-jobs':   '학습 잡',
  'model-promotion': '모델 승급',
  'eval-policy':     '평가 정책',
  'eval-jobs':       '평가 잡',
  'inference':       '추론',
  'monitoring':      '모니터링',
  'catalog':         '카탈로그',
};

// Which group-id contains the given page?
function groupForPage(page: PageId): string | null {
  for (const node of NAV_NODES) {
    if (node.kind === 'group') {
      if (node.children.some((c) => c.id === page)) return node.id;
    }
  }
  return null;
}

// Phase → Clarity label class
function phaseLabelClass(phase: string): string {
  const p = (phase ?? '').toLowerCase();
  if (['ready', 'active', 'running'].some((k) => p.includes(k))) return 'label-success';
  if (['draft', 'mock', 'planned', 'pending'].some((k) => p.includes(k))) return 'label';
  if (['waitingeval', 'waiting'].some((k) => p.includes(k))) return 'label-info';
  if (['failed', 'error'].some((k) => p.includes(k))) return 'label-danger';
  return 'label';
}

// Alert severity → Clarity alert type
function alertType(severity: string): string {
  const s = (severity ?? '').toLowerCase();
  if (s === 'error' || s === 'danger') return 'alert-danger';
  if (s === 'warning') return 'alert-warning';
  if (s === 'success') return 'alert-success';
  return 'alert-info';
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------
@Component({
  selector: 'osp-ai-shell-root',
  standalone: true,
  imports: [ClarityModule],
  styleUrls: ['./ai-shell.element.css'],
  template: `
    <div class="ai-app">

      <!-- ── Left nav: Clarity vertical nav (cluster nav 동일 구현) ── -->
      <clr-vertical-nav class="os-sidebar-nav" [clrVerticalNavCollapsible]="false">
        <!-- 브랜드 헤더 -->
        <div class="os-brand">AI Level <span class="label label-info">Angular</span></div>

        @for (node of navNodes; track node.id) {
          @if (node.kind === 'leaf') {
            <!-- 단독 leaf 링크 -->
            <a clrVerticalNavLink
               [class.active]="activePage() === node.id"
               (click)="navigate(node.id)"
               (keydown.enter)="navigate(node.id)">
              <svg viewBox="0 0 24 24" class="os-tree-ic" clrVerticalNavIcon><path [attr.d]="icon(node.id)"/></svg>
              {{ node.label }}
            </a>
          } @else {
            <!-- 그룹 -->
            <clr-vertical-nav-group
                [clrVerticalNavGroupExpanded]="isOpen(node.id)"
                (clrVerticalNavGroupExpandedChange)="setOpen(node.id, $event)">
              <svg viewBox="0 0 24 24" class="os-tree-ic" clrVerticalNavIcon><path [attr.d]="icon(node.id)"/></svg>
              {{ node.label }}
              <clr-vertical-nav-group-children>
                @for (child of node.children; track child.id) {
                  <a clrVerticalNavLink
                     [class.active]="activePage() === child.id"
                     (click)="navigate(child.id)"
                     (keydown.enter)="navigate(child.id)">
                    <svg viewBox="0 0 24 24" class="os-tree-ic os-tree-ic-child" clrVerticalNavIcon><path [attr.d]="icon(child.id)"/></svg>
                    {{ child.label }}
                  </a>
                }
              </clr-vertical-nav-group-children>
            </clr-vertical-nav-group>
          }
        }
      </clr-vertical-nav>

      <!-- ── Right content ──────────────────────────────────────── -->
      <div class="ai-content">

        <!-- Top header bar -->
        <div class="ai-topbar">
          <div class="ai-topbar-title">
            <p class="ai-eyebrow">OPENSPHERE AI</p>
            <h1>AI Operations</h1>
          </div>
          <div class="ai-topbar-chips">
            @if (summary()) {
              <span class="label label-info">{{ summary()!.phase }}</span>
            } @else {
              <span class="label label-info">Phase 0</span>
            }
            <span class="label">single signed bundle</span>
            <span class="label label-warning">read-only</span>
          </div>
        </div>

        <!-- Alert banner (summary.alerts) — Clarity <clr-alert> -->
        @if (summary()?.alerts?.length) {
          @for (alert of summary()!.alerts; track alert.message) {
            <clr-alert [clrAlertType]="alertType(alert.severity)" [clrAlertClosable]="false">
              <clr-alert-item>
                <span class="alert-text">{{ alert.message }}</span>
              </clr-alert-item>
            </clr-alert>
          }
        }

        <!-- ── HOME PAGE ──────────────────────────────────────── -->
        @if (activePage() === 'home') {
          <div class="page-home">

            <!-- Section 1: AI 에이전트 -->
            <div class="card">
              <div class="card-header">
                <div class="section-header">
                  <span class="section-icon">⚙</span>
                  <div>
                    <h2 class="section-title">AI 에이전트</h2>
                    <p class="section-sub">등록된 에이전트 런타임과 도구</p>
                  </div>
                  <a
                    class="label clickable section-link-right"
                    href="javascript:void(0)"
                    (click)="navigate('agents')"
                  >에이전트 목록 →</a>
                </div>
              </div>
              <div class="card-block">
                @if (loadingAgents()) {
                  <div class="loading-row">에이전트 목록을 불러오는 중…</div>
                } @else {
                  <div class="card-grid">
                    @for (agent of agents(); track agent.name) {
                      <div class="card">
                        <div class="card-block">
                          <div class="card-title">{{ agent.name }}</div>
                          <p class="card-text">
                            <span class="label {{ phaseLabelClass(agent.phase) }}">{{ agent.phase }}</span>
                            &nbsp;
                            <span class="ready-indicator {{ agent.ready ? 'ready-indicator--ok' : '' }}">
                              {{ agent.ready ? '✓ Ready' : '– Not Ready' }}
                            </span>
                          </p>
                          <p class="card-text-kind">{{ agent.kind }}</p>
                        </div>
                      </div>
                    }
                    @if (!agents().length) {
                      <div class="card">
                        <div class="card-block">
                          <div class="card-title">등록된 에이전트 없음</div>
                          <p class="card-text">에이전트를 추가하려면 관리자에게 요청하세요.</p>
                          <button type="button" class="btn btn-sm btn-outline" disabled>
                            에이전트 추가 요청 (write 금지)
                          </button>
                        </div>
                      </div>
                    }
                    <!-- 추가 안내 카드 -->
                    <div class="card">
                      <div class="card-block">
                        <div class="card-title">에이전트 추가?</div>
                        <p class="card-text">관리자에게 요청하세요 (write 금지)</p>
                        <button type="button" class="btn btn-sm btn-outline" disabled>요청하기</button>
                      </div>
                    </div>
                  </div>
                }
              </div>
            </div>

            <!-- Section 2: 학습·서빙·평가·관리 -->
            <div class="card">
              <div class="card-header">
                <div class="section-header">
                  <span class="section-icon">▲</span>
                  <div>
                    <h2 class="section-title">학습 · 서빙 · 평가 · 관리</h2>
                    <p class="section-sub">AI 운영 핵심 작업 영역</p>
                  </div>
                </div>
              </div>
              <div class="card-block">
                <div class="action-card-grid">

                  <div class="card card-clickable"
                       role="button" tabindex="0"
                       (click)="navigate('llm-routes')"
                       (keyup.enter)="navigate('llm-routes')">
                    <div class="card-block">
                      <div class="card-media-block">
                        <span class="action-icon">⬡</span>
                        <div class="card-media-description action-card-body">
                          <span class="card-media-title">Foundation AI</span>
                          <p class="action-card-desc">LLM 라우트 · 검색 인덱스 · 임베딩</p>
                          <span class="action-count">
                            LLM 라우트 {{ summary()?.counts?.llmRoutes ?? 0 }}개
                          </span>
                        </div>
                        <span class="action-arrow">→</span>
                      </div>
                    </div>
                  </div>

                  <div class="card card-clickable"
                       role="button" tabindex="0"
                       (click)="navigate('agents')"
                       (keyup.enter)="navigate('agents')">
                    <div class="card-block">
                      <div class="card-media-block">
                        <span class="action-icon">⚙</span>
                        <div class="card-media-description action-card-body">
                          <span class="card-media-title">에이전트 · 오케스트레이션</span>
                          <p class="action-card-desc">에이전트 런타임 · 도구 등록 · 워크플로우</p>
                          <span class="action-count">
                            에이전트 {{ summary()?.counts?.agents ?? 0 }}개
                          </span>
                        </div>
                        <span class="action-arrow">→</span>
                      </div>
                    </div>
                  </div>

                  <div class="card card-clickable"
                       role="button" tabindex="0"
                       (click)="navigate('training-jobs')"
                       (keyup.enter)="navigate('training-jobs')">
                    <div class="card-block">
                      <div class="card-media-block">
                        <span class="action-icon">◈</span>
                        <div class="card-media-description action-card-body">
                          <span class="card-media-title">학습 · 모델</span>
                          <p class="action-card-desc">데이터셋 · 컴퓨트 · 파인튜닝 잡</p>
                          <span class="action-count">
                            학습 잡 {{ summary()?.counts?.trainingJobs ?? 0 }}개
                          </span>
                        </div>
                        <span class="action-arrow">→</span>
                      </div>
                    </div>
                  </div>

                  <div class="card card-clickable"
                       role="button" tabindex="0"
                       (click)="navigate('eval-jobs')"
                       (keyup.enter)="navigate('eval-jobs')">
                    <div class="card-block">
                      <div class="card-media-block">
                        <span class="action-icon">✓</span>
                        <div class="card-media-description action-card-body">
                          <span class="card-media-title">평가 · 추론</span>
                          <p class="action-card-desc">골든셋 게이트 · 서빙 엔드포인트</p>
                          <span class="action-count">
                            평가 잡 {{ summary()?.counts?.evaluationJobs ?? 0 }}개
                            · 추론 {{ summary()?.counts?.inferenceEndpoints ?? 0 }}개
                          </span>
                        </div>
                        <span class="action-arrow">→</span>
                      </div>
                    </div>
                  </div>

                </div>
              </div>
            </div>

            <!-- Section 3: AI 애드온 · 리소스 -->
            <div class="card">
              <div class="card-header">
                <div class="section-header">
                  <span class="section-icon">☰</span>
                  <div>
                    <h2 class="section-title">AI 애드온 · 리소스</h2>
                    <p class="section-sub">카탈로그 · 문서 · 가이드</p>
                  </div>
                  <a
                    class="label clickable section-link-right"
                    href="javascript:void(0)"
                    (click)="navigate('catalog')"
                  >카탈로그 전체 보기 →</a>
                </div>
              </div>
              <div class="card-block">
                @if (loadingCatalog()) {
                  <div class="loading-row">카탈로그를 불러오는 중…</div>
                } @else {
                  <div class="addon-grid">
                    @for (item of catalogItems(); track item.name) {
                      <div class="card">
                        <div class="card-block">
                          <div class="addon-card-top">
                            <span class="addon-icon">☰</span>
                            <span class="label {{ phaseLabelClass(item.phase) }}">{{ item.phase }}</span>
                          </div>
                          <div class="card-title">{{ item.name }}</div>
                          <p class="addon-kind">{{ item.kind }}</p>
                          <a class="card-link" href="#">문서 보기 →</a>
                        </div>
                      </div>
                    }
                    <!-- 정적 문서 카드 -->
                    <div class="card">
                      <div class="card-block">
                        <div class="addon-card-top">
                          <span class="addon-icon">📖</span>
                          <span class="label">Docs</span>
                        </div>
                        <div class="card-title">OpenSphere AI 아키텍처 가이드</div>
                        <p class="addon-kind">공식 문서</p>
                        <a class="card-link" href="#">가이드 열기 →</a>
                      </div>
                    </div>
                    <div class="card">
                      <div class="card-block">
                        <div class="addon-card-top">
                          <span class="addon-icon">🔧</span>
                          <span class="label">Tutorial</span>
                        </div>
                        <div class="card-title">에이전트 온보딩 튜토리얼</div>
                        <p class="addon-kind">시작 가이드</p>
                        <a class="card-link" href="#">튜토리얼 →</a>
                      </div>
                    </div>
                    <div class="card">
                      <div class="card-block">
                        <div class="addon-card-top">
                          <span class="addon-icon">📊</span>
                          <span class="label">Reference</span>
                        </div>
                        <div class="card-title">API 레퍼런스</div>
                        <p class="addon-kind">개발자 문서</p>
                        <a class="card-link" href="#">API 문서 →</a>
                      </div>
                    </div>
                  </div>
                }
              </div>
            </div>

          </div>
        }

        <!-- ── RESOURCE PAGES (모든 non-home 페이지) ─────────── -->
        @if (activePage() !== 'home') {
          <div class="page-resource">
            <div class="resource-page-header">
              <div>
                <p class="ai-eyebrow">{{ pageLabel() }}</p>
                <h2>{{ pageLabel() }}</h2>
              </div>
              <button type="button" class="btn btn-primary" disabled>생성 (write 금지)</button>
            </div>

            @if (loadingResource()) {
              <div class="loading-row">데이터를 불러오는 중…</div>
            } @else {
              <!-- Clarity datagrid for resource list -->
              <clr-datagrid>
                <clr-dg-column>이름</clr-dg-column>
                <clr-dg-column>Kind</clr-dg-column>
                <clr-dg-column>Phase</clr-dg-column>
                <clr-dg-column>Ready</clr-dg-column>

                @for (item of resourceItems(); track item.name) {
                  <clr-dg-row>
                    <clr-dg-cell>{{ item.name }}</clr-dg-cell>
                    <clr-dg-cell>{{ item.kind }}</clr-dg-cell>
                    <clr-dg-cell>
                      <span class="label {{ phaseLabelClass(item.phase) }}">{{ item.phase }}</span>
                    </clr-dg-cell>
                    <clr-dg-cell>{{ item.ready ? '✓' : '–' }}</clr-dg-cell>
                  </clr-dg-row>
                }

                @if (!resourceItems().length) {
                  <clr-dg-placeholder>항목 없음 — API에서 데이터를 받지 못했습니다.</clr-dg-placeholder>
                }

                <clr-dg-footer>
                  <clr-dg-pagination [clrDgPageSize]="20">
                    {{ resourceItems().length }} 항목
                  </clr-dg-pagination>
                </clr-dg-footer>
              </clr-datagrid>
            }
          </div>
        }

      </div><!-- /ai-content -->
    </div><!-- /ai-app -->
  `,
})
export class AiShellElement implements OnInit {
  readonly navNodes = NAV_NODES;

  // ---- Signals ----
  readonly activePage    = signal<PageId>(this.initialPage());
  readonly openGroups    = signal<Set<string>>(this.initialOpenGroups());
  readonly summary       = signal<SummaryResponse | null>(null);
  readonly agents        = signal<ResourceItem[]>([]);
  readonly catalogItems  = signal<ResourceItem[]>([]);
  readonly resourceItems = signal<ResourceItem[]>([]);

  readonly loadingAgents   = signal(false);
  readonly loadingCatalog  = signal(false);
  readonly loadingResource = signal(false);

  // Computed: display label for current resource page
  readonly pageLabel = computed(() => PAGE_LABEL[this.activePage()] ?? '');

  // ---- Helpers (exposed to template) ----
  readonly phaseLabelClass = phaseLabelClass;
  readonly alertType = alertType;

  // cluster nav 동일 메서드
  icon(id: string): string { return NAV_ICON[id] || NAV_ICON['fallback']; }
  isOpen(id: string): boolean { return this.openGroups().has(id); }
  setOpen(id: string, open: boolean): void {
    this.openGroups.update(s => { const n = new Set(s); open ? n.add(id) : n.delete(id); return n; });
  }

  // ---- API base ----
  private get apiBase(): string {
    if (typeof window === 'undefined') return '';
    return (window as Window & { __OSP_AI_API_BASE__?: string }).__OSP_AI_API_BASE__ ?? '';
  }

  // ---- Lifecycle ----
  ngOnInit(): void {
    this.fetchSummary();
    this.fetchAgents();
    this.fetchCatalog();
    if (this.activePage() !== 'home') {
      this.fetchResourcePage(this.activePage());
    }
  }

  // ---- Navigation ----
  navigate(page: PageId): void {
    this.activePage.set(page);
    // Auto-open the group that contains this page
    const gid = groupForPage(page);
    if (gid && !this.openGroups().has(gid)) {
      const current = new Set(this.openGroups());
      current.add(gid);
      this.openGroups.set(current);
    }
    if (page !== 'home') {
      this.fetchResourcePage(page);
    }
  }

  // ---- Fetches ----
  private async fetchSummary(): Promise<void> {
    try {
      const res = await fetch(`${this.apiBase}/summary`);
      if (!res.ok) return;
      const data: SummaryResponse = await res.json();
      this.summary.set(data);
    } catch {
      // graceful: keep null
    }
  }

  private async fetchAgents(): Promise<void> {
    this.loadingAgents.set(true);
    try {
      const res = await fetch(`${this.apiBase}/resources/agents`);
      if (!res.ok) { this.loadingAgents.set(false); return; }
      const data: ResourceListResponse = await res.json();
      this.agents.set(data.items ?? []);
    } catch {
      // graceful empty
    } finally {
      this.loadingAgents.set(false);
    }
  }

  private async fetchCatalog(): Promise<void> {
    this.loadingCatalog.set(true);
    try {
      const res = await fetch(`${this.apiBase}/catalog`);
      if (!res.ok) { this.loadingCatalog.set(false); return; }
      const data: ResourceListResponse = await res.json();
      this.catalogItems.set(data.items ?? []);
    } catch {
      // graceful empty
    } finally {
      this.loadingCatalog.set(false);
    }
  }

  private async fetchResourcePage(page: PageId): Promise<void> {
    const path = RESOURCE_PATH[page];
    if (!path) { this.resourceItems.set([]); return; }

    this.loadingResource.set(true);
    try {
      const res = await fetch(`${this.apiBase}/${path}`);
      if (!res.ok) { this.loadingResource.set(false); return; }
      const data: ResourceListResponse = await res.json();
      this.resourceItems.set(data.items ?? []);
    } catch {
      this.resourceItems.set([]);
    } finally {
      this.loadingResource.set(false);
    }
  }

  // ---- Initial page from URL ----
  private initialPage(): PageId {
    const path = (typeof window !== 'undefined') ? window.location.pathname : '';
    if (path.includes('/llm-routes'))      return 'llm-routes';
    if (path.includes('/retrieval'))       return 'retrieval';
    if (path.includes('/agents'))          return 'agents';
    if (path.includes('/compute'))         return 'compute';
    if (path.includes('/datasets'))        return 'datasets';
    if (path.includes('/training-jobs'))   return 'training-jobs';
    if (path.includes('/training'))        return 'training-jobs';  // legacy
    if (path.includes('/model-promotion')) return 'model-promotion';
    if (path.includes('/models'))          return 'model-promotion'; // legacy
    if (path.includes('/eval-policy'))     return 'eval-policy';
    if (path.includes('/eval-jobs'))       return 'eval-jobs';
    if (path.includes('/evaluation'))      return 'eval-jobs';      // legacy
    if (path.includes('/inference'))       return 'inference';
    if (path.includes('/monitoring'))      return 'monitoring';
    if (path.includes('/catalog'))         return 'catalog';
    if (path.includes('/foundation'))      return 'llm-routes';     // legacy
    return 'home';
  }

  // ---- Initial open groups (open the group containing the active page) ----
  private initialOpenGroups(): Set<string> {
    const page = this.initialPage();
    const gid = groupForPage(page);
    return gid ? new Set([gid]) : new Set();
  }
}
