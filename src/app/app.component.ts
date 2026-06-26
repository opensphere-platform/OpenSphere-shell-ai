import { Component, ViewEncapsulation } from '@angular/core';

// SDK 표준 빈 골격 placeholder. ShadowDom 인캡슐레이션 → 셸 CSS 영향 0(자체완결).
// 내용은 인스턴스화 후 작성(컴포넌트·nav·resources 등).
@Component({
  selector: 'app-root',
  standalone: true,
  encapsulation: ViewEncapsulation.ShadowDom,
  template: `<section style="padding:1rem"><h2>AI subShell</h2><p>SDK 표준 골격 — 내용 후속(placeholder)</p></section>`,
})
export class AppComponent {}
