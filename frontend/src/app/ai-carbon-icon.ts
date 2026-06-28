import { ChangeDetectionStrategy, Component, Input, inject } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

export interface AiIconNode {
  elem: string;
  attrs?: Record<string, unknown>;
  content?: AiIconNode[];
}

@Component({
  selector: 'ai-cicon',
  standalone: true,
  template: `<span class="ai-cicon" [innerHTML]="html"></span>`,
  changeDetection: ChangeDetectionStrategy.OnPush,
  styles: [
    `
      :host {
        display: inline-flex;
        line-height: 0;
      }
      .ai-cicon {
        display: inline-flex;
        line-height: 0;
      }
      .ai-cicon ::ng-deep svg {
        fill: currentColor;
      }
    `,
  ],
})
export class AiCarbonIcon {
  private readonly sanitizer = inject(DomSanitizer);
  html: SafeHtml = '';
  private descriptor?: AiIconNode;
  private iconSize = 16;

  @Input({ required: true }) set icon(value: AiIconNode) {
    this.descriptor = value;
    this.render();
  }

  @Input() set size(value: number) {
    this.iconSize = value;
    this.render();
  }

  private render(): void {
    if (!this.descriptor) return;
    const root: AiIconNode = {
      ...this.descriptor,
      attrs: { ...this.descriptor.attrs, width: this.iconSize, height: this.iconSize },
    };
    this.html = this.sanitizer.bypassSecurityTrustHtml(this.toString(root));
  }

  private toString(node: AiIconNode): string {
    const attrs = Object.entries(node.attrs || {})
      .map(([key, value]) => `${key}="${String(value)}"`)
      .join(' ');
    const children = (node.content || []).map((child) => this.toString(child)).join('');
    return `<${node.elem} ${attrs}>${children}</${node.elem}>`;
  }
}
