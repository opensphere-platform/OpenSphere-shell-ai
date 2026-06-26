import { createApplication } from '@angular/platform-browser';
import { provideAnimations } from '@angular/platform-browser/animations';
import { createCustomElement } from '@angular/elements';
import { AiShellElement } from './app/ai-shell.element';

const TAG = 'osp-ai-shell';

(async () => {
  // provideAnimations() 필수 — Clarity clr-vertical-nav-group 접기는 Angular 애니메이션 기반.
  // 없으면 그룹 children이 안 접혀 트리가 평평한 목록처럼 보인다(foundation/cluster/shell엔 이미 있음).
  const app = await createApplication({ providers: [provideAnimations()] });
  const el = createCustomElement(AiShellElement, { injector: app.injector });
  if (!customElements.get(TAG)) customElements.define(TAG, el);
})();
