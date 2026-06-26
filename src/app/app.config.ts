import { ApplicationConfig, provideZonelessChangeDetection } from '@angular/core';
import { provideHttpClient } from '@angular/common/http';
import { provideAnimations } from '@angular/platform-browser/animations';

// zoneless: zone.js 없이 동작 → 셸(Angular, zone 사용)과 같은 DOM(DUPA)에 마운트해도
// zone.js 이중 패치 충돌이 없음. (signals 기반 변경감지)
export const appConfig: ApplicationConfig = {
  providers: [provideZonelessChangeDetection(), provideHttpClient(), provideAnimations()],
};
