// dsh 浏览器侧插件：在设置页注册 dsh-passwords 独立设置分区（settings.section），
// 分区体内渲染设置卡片（见下方 settings.section 注册）。
// 卡片内容：
//   - 远程设置补丁状态（所有用户可见）+ "重载补丁"按钮（仅主用户可触发；补丁强制启用）
//   - 用户管理（改密/改名/子用户） → fetch /api/dsh-passwords/*（网关
//     JWT cookie 鉴权）
import type { Context as ClientContext } from '@deepseek-ai/cordis';
import type {} from '@deepseek-ai/dsh-api-session-controller/client';
import type {} from '@deepseek-ai/dsh-api-workspace-controller/client';
import type {} from '@deepseek-ai/dsh-client-locale/client';
import type {} from '@deepseek-ai/dsh-client-ui-conversation/client';
import type {} from '@deepseek-ai/dsh-client-ui-layout/client';
import type {} from '@deepseek-ai/dsh-client-ui-renderer/client';
import type {} from '@deepseek-ai/dsh-client-ui-settings/client';
import type {} from '@deepseek-ai/dsh-client-ui-settings-general/client';
import type {} from '@deepseek-ai/dsh-client-ui-slots';

// dsh-passwords owns these extension slots; keep their declarations local so
// the compiler verifies the same registration keys used by the runtime.
declare module '@deepseek-ai/dsh-client-ui-slots' {
  interface SlotMap {
    'dsh-passwords.plugin.item': {
      kind: 'list';
      scope: 'root';
    };
  }
}
import { DshPasswordsCard } from './card';
import { DshPasswordsSection } from './section';
import { ChatLauncher } from './chat';
import { TokenReporter } from './token';
import { zh, en } from './locales';

/** 卡片样式：全部使用 dsh 设计令牌（--dsw-alias-*），颜色/主题与官方 PluginCard 完全一致 */
const CSS = `
.dshpw-card{--dshpw-accent:var(--dsw-alias-brand-primary,#14b8a6);--dshpw-ink:var(--dsw-alias-label-primary,#172026);--dshpw-inverted:var(--dsw-alias-label-primary-inverted,#fff);--dshpw-muted:var(--dsw-alias-label-tertiary,#74808a);--dshpw-line:var(--dsw-alias-border-l2,#e3e7e9);--dshpw-surface:var(--dsw-alias-bg-layer-2,#f8fafb);--dshpw-layer:var(--dsw-alias-bg-layer-3,#fff);--dshpw-success:var(--dsw-alias-semantic-success,#10b981);--dshpw-warning:var(--dsw-alias-semantic-warning,#f59e0b);--dshpw-danger:var(--dsw-alias-semantic-danger,#ef4444);display:flex;flex-direction:column;border:1px solid var(--dshpw-line);border-radius:14px;background:var(--dshpw-layer);box-shadow:0 8px 24px rgb(0 0 0 / 8%);transition:border-color .2s,box-shadow .2s;font-size:13px;line-height:1.5;overflow:hidden;color:var(--dshpw-ink)}
.dshpw-card:hover{border-color:color-mix(in srgb,var(--dshpw-accent) 35%,var(--dshpw-line));box-shadow:0 12px 30px rgb(0 0 0 / 12%)}
.dshpw-body{display:flex;flex-direction:column;gap:0;padding:10px 20px 24px}
.dshpw-section{display:flex;flex-direction:column;gap:12px;padding:20px 0;border-top:1px solid var(--dshpw-line)}
.dshpw-section:first-child{border-top:0}
.dshpw-section-head{display:flex;align-items:center;justify-content:space-between;gap:16px;min-height:28px}
.dshpw-section-title{display:flex;align-items:center;gap:8px;min-width:0}
.dshpw-label{display:block;font-size:12px;font-weight:700;letter-spacing:.02em;color:var(--dshpw-muted);text-transform:none}
.dshpw-action-row{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
.dshpw-action-copy{flex:1;min-width:180px}
.dshpw-patch-actions{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.dshpw-patch-actions>.dshpw-action-row{width:100%}
.dshpw-update-actions{display:flex;align-items:center;justify-content:flex-end;flex-wrap:nowrap}.dshpw-update-actions.has-progress{display:grid;grid-template-columns:minmax(0,1fr) auto auto;flex-wrap:nowrap}
.dshpw-update-inline-progress{display:flex;align-items:center;gap:8px;min-width:0;width:100%}
.dshpw-update-inline-progress .dshpw-hint{white-space:nowrap}
.dshpw-update-manual-block{display:flex;flex-direction:column;gap:6px}.dshpw-update-manual-command{overflow-wrap:anywhere;padding:8px 10px;border:1px solid var(--dshpw-line);border-radius:8px;background:var(--dshpw-surface);font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
.dshpw-update-apply{min-width:96px}
.dshpw-progress-track{height:8px;flex:1;min-width:72px;overflow:hidden;border-radius:4px;background:var(--dshpw-line)}
.dshpw-progress-fill{display:block;height:100%;border-radius:inherit;background:var(--dshpw-accent);transition:width .25s ease}
.dshpw-progress-track.indeterminate .dshpw-progress-fill{width:38%;animation:dshpwProgress 1.1s ease-in-out infinite}
@keyframes dshpwProgress{from{transform:translateX(-110%)}to{transform:translateX(290%)}}
@media(max-width:640px){.dshpw-update-actions.has-progress{grid-template-columns:minmax(0,1fr) auto auto;gap:6px}.dshpw-update-inline-progress{min-width:0}.dshpw-update-inline-progress .dshpw-hint{display:none}.dshpw-update-apply{min-width:0}.dshpw-update-actions>.dshpw-btn{min-width:0;padding-inline:9px}.dshpw-update-manual-command{font-size:11px}}
.dshpw-form-actions{justify-content:flex-end}
.dshpw-preference{padding-top:14px}
.dshpw-profile{display:flex;align-items:center;gap:12px;padding:10px 0 18px;border-bottom:1px solid var(--dshpw-line)}
.dshpw-avatar{display:grid;place-items:center;width:38px;height:38px;border-radius:11px;background:var(--dshpw-accent);color:var(--dshpw-inverted);font-size:16px;font-weight:700;flex:none}
.dshpw-profile-copy{display:flex;flex-direction:column;gap:1px;min-width:0}
.dshpw-profile-label{font-size:12px;color:var(--dshpw-muted)}
.dshpw-profile-copy strong{font-size:15px;line-height:1.3;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dshpw-signout{margin-left:auto}
.dshpw-status{display:inline-flex;align-items:center;gap:5px;padding:3px 9px;border-radius:999px;font-size:11px;font-weight:650;white-space:nowrap}
.dshpw-status-neutral{background:color-mix(in srgb,var(--dshpw-muted) 12%,transparent);color:var(--dshpw-muted)}
.dshpw-status-success{background:color-mix(in srgb,var(--dshpw-success) 14%,transparent);color:var(--dshpw-success)}
.dshpw-status-warning{background:color-mix(in srgb,var(--dshpw-warning) 16%,transparent);color:var(--dshpw-warning)}
.dshpw-status-danger{background:color-mix(in srgb,var(--dshpw-danger) 14%,transparent);color:var(--dshpw-danger)}
.dshpw-update-status{display:inline-flex;align-items:center;gap:6px}
.dshpw-spinner{display:inline-block;width:12px;height:12px;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;animation:dshpwSpin .7s linear infinite;vertical-align:-2px}
@keyframes dshpwSpin{to{transform:rotate(360deg)}}
.dshpw-switch{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:13px 14px;border:1px solid var(--dshpw-line);border-radius:11px;background:var(--dshpw-surface);cursor:pointer;transition:border-color .2s,background .2s,transform .2s}
.dshpw-switch:hover{border-color:color-mix(in srgb,var(--dshpw-accent) 45%,var(--dshpw-line));background:var(--dshpw-layer);transform:translateY(-1px)}
.dshpw-switch-copy{display:flex;flex-direction:column;gap:3px;min-width:0;color:var(--dshpw-ink)}
.dshpw-switch-copy strong{font-size:13px;font-weight:650;line-height:1.35}
.dshpw-switch-copy small{font-size:12px;line-height:1.4;color:var(--dshpw-muted)}
.dshpw-switch-control{position:relative;display:inline-flex;flex:0 0 auto;width:42px;height:24px}
.dshpw-switch-control input{position:absolute;width:1px;height:1px;opacity:0}
.dshpw-switch-track{position:absolute;inset:0;border-radius:999px;background:var(--dshpw-line);transition:background .2s,box-shadow .2s}
.dshpw-switch-thumb{position:absolute;top:3px;left:3px;width:18px;height:18px;border-radius:50%;background:var(--dshpw-layer);box-shadow:0 1px 4px rgb(0 0 0 / 22%);transition:transform .2s}
.dshpw-switch-control input:checked + .dshpw-switch-track{background:var(--dshpw-accent);box-shadow:0 0 0 3px color-mix(in srgb,var(--dshpw-accent) 15%,transparent)}
.dshpw-switch-control input:checked + .dshpw-switch-track .dshpw-switch-thumb{transform:translateX(18px)}
.dshpw-switch-control input:focus-visible + .dshpw-switch-track{outline:2px solid var(--dshpw-accent);outline-offset:3px}
.dshpw-input{width:100%;box-sizing:border-box;min-width:0;padding:9px 11px;font-size:13px;color:var(--dshpw-ink);background:var(--dshpw-surface);border:1px solid var(--dshpw-line);border-radius:9px;transition:border-color .2s,box-shadow .2s,background .2s}
.dshpw-input:hover{border-color:color-mix(in srgb,var(--dshpw-ink) 32%,var(--dshpw-line));background:var(--dshpw-layer)}
.dshpw-input:focus{outline:none;border-color:var(--dshpw-accent);background:var(--dshpw-layer);box-shadow:0 0 0 3px color-mix(in srgb,var(--dshpw-accent) 16%,transparent)}
.dshpw-input::placeholder{color:var(--dshpw-muted)}
.dshpw-btn{appearance:none;border:1px solid transparent;border-radius:9px;padding:8px 14px;font-size:13px;line-height:1.35;font-weight:650;background:var(--dshpw-accent);color:var(--dshpw-inverted);cursor:pointer;white-space:nowrap;transition:background .2s,filter .2s,transform .1s,box-shadow .2s}
.dshpw-btn:active:not(:disabled){transform:translateY(1px)}
.dshpw-btn:hover:not(:disabled){filter:brightness(1.12);box-shadow:0 4px 12px rgb(0 0 0 / 12%)}
.dshpw-btn:focus-visible{outline:2px solid var(--dshpw-accent);outline-offset:2px}
.dshpw-btn:disabled{opacity:.45;cursor:default;box-shadow:none}
.dshpw-btn.danger{background:transparent;border-color:var(--dshpw-danger);color:var(--dshpw-danger)}
.dshpw-btn.danger:hover:not(:disabled){filter:none;background:color-mix(in srgb,var(--dshpw-danger) 12%,transparent)}
.dshpw-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.dshpw-user{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--dshpw-line)}
.dshpw-user:last-child{border-bottom:none}
.dshpw-perm{border:1px solid var(--dshpw-line);border-radius:11px;padding:14px;display:flex;flex-direction:column;gap:10px;background:var(--dshpw-surface)}
.dshpw-perm-head{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.dshpw-workspaces{display:flex;flex-direction:column;gap:8px}
.dshpw-workspace{border:1px solid var(--dshpw-line);border-radius:9px;overflow:hidden;background:var(--dshpw-layer)}
.dshpw-workspace-switch{border:0;border-radius:0;background:transparent}
.dshpw-workspace-switch:hover{background:var(--dshpw-surface)}
.dshpw-session-list{display:flex;flex-direction:column;gap:6px;padding:10px 12px 12px 18px;border-top:1px solid var(--dshpw-line)}
.dshpw-session-check{display:flex;align-items:center;gap:8px;font-size:12px;color:var(--dshpw-muted);cursor:pointer;min-height:28px}
.dshpw-session-check input,.dshpw-check input{accent-color:var(--dshpw-accent)}
.dshpw-session-check span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dshpw-check{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--dshpw-muted);cursor:pointer}
select.dshpw-input{height:auto;min-height:38px}
.dshpw-badge{font-size:11px;padding:3px 8px;border-radius:999px;border:1px solid color-mix(in srgb,var(--dshpw-accent) 45%,transparent);color:var(--dshpw-success);background:color-mix(in srgb,var(--dshpw-success) 14%,transparent);margin-left:6px;white-space:nowrap}
.dshpw-badge.admin{border-color:color-mix(in srgb,var(--dshpw-warning) 55%,transparent);color:var(--dshpw-warning);background:color-mix(in srgb,var(--dshpw-warning) 16%,transparent)}
.dshpw-error{color:var(--dshpw-danger);font-size:12px}
.dshpw-ok{color:var(--dshpw-success);font-size:12px}
.dshpw-hint{font-size:12px;line-height:1.5;color:var(--dshpw-muted)}
@media (prefers-reduced-motion:reduce){.dshpw-card,.dshpw-btn,.dshpw-switch,.dshpw-input,.dshpw-spinner{transition:none;animation:none}}
@media (max-width:560px){.dshpw-body{padding:6px 14px 18px}.dshpw-section{padding:16px 0}.dshpw-action-row{align-items:stretch}.dshpw-action-row .dshpw-btn{width:100%}.dshpw-patch-actions .dshpw-btn{width:100%}.dshpw-signout{width:auto!important}.dshpw-section-head{align-items:flex-start;flex-direction:column;gap:7px}.dshpw-status{max-width:100%;white-space:normal}.dshpw-profile{align-items:flex-start}.dshpw-profile .dshpw-signout{margin-left:auto}}
`;

export const inject = ['slots', 'locale'] as const;

export function apply(ctx: ClientContext): void {
  ctx.effect(() => {
    if (typeof document === 'undefined') return () => {};
    const existing = document.querySelector('style[data-dshpw-style="1"]');
    if (existing) return () => {};
    const el = document.createElement('style');
    el.dataset.dshpwStyle = '1';
    el.textContent = CSS;
    document.head.appendChild(el);
    return () => el.remove();
  }, 'dsh-passwords: styles');

  // 独立设置分区（settings.section）：在设置页左侧导航注册 dsh-passwords
  // 一级分区，分区体内渲染注册进 dsh-passwords.plugin.item 的卡片——设置
  // 不再挤在官方"插件"列表里，而是单独成区。
  ctx.slots.inject('settings.section', () =>
    ctx.slots.register(
      {
        name: 'settings.section',
        id: 'dsh-passwords',
        order: 105,
        label: () => ctx.locale.bind('dshpw')('sectionTitle'),
        locale: 'dshpw',
        children: { 'dsh-passwords.plugin.item': { kind: 'list', scope: 'root' } },
      },
      DshPasswordsSection,
    ),
  );

  // 设置卡片：注册进上面分区声明的子槽（分区体 renderSlot 渲染）
  ctx.slots.inject('dsh-passwords.plugin.item', () =>
    ctx.slots.register(
      {
        name: 'dsh-passwords.plugin.item',
        id: 'dsh-passwords-card',
        order: 55,
        locale: 'dshpw',
      },
      DshPasswordsCard,
    ),
  );

  // 全局聊天入口：左下角圆形按钮 + 居中弹窗（shell.overlay 槽，root 作用域）
  ctx.slots.inject('shell.overlay', () =>
    ctx.slots.register(
      {
        name: 'shell.overlay',
        id: 'dsh-passwords-chat',
        order: 100,
        locale: 'dshpw',
      },
      ChatLauncher,
    ),
  );

  // 不可见 token 上报器：会话作用域（conversation.composer.dock 供应 useProjection），
  // 读取 dsh 的 tokenUsage 投影并把增量上报给密码门，用于子用户每小时 token 配额。
  ctx.slots.inject('conversation.composer.dock', () =>
    ctx.slots.register(
      { name: 'conversation.composer.dock', id: 'dsh-passwords-token', order: 90 },
      TokenReporter,
    ),
  );

  // ── 远程文件下载（Issue #4）──────────────────────────────────
  // 经 dsh-passwords 网关远程访问时，点击对话里的“生成文件”标签会调用
  // workspaces.openPath → host.openPath → 服务器容器里 xdg-open（无桌面环境
  // → spawn xdg-open ENOENT）。这里包装 openPath：检测到经网关访问时改为
  // 跳转 /gateway/api/download 下载到浏览器；本地桌面访问保持原 RPC 行为。
  // 网关检测：探测一次响应头 X-Dsh-Gateway（网关在代理/自身响应里注入）。
  let gatewayDetected: boolean | null = null;
  const isBehindGateway = async (): Promise<boolean> => {
    if (gatewayDetected !== null) return gatewayDetected;
    try {
      const resp = await fetch('/gateway/login', {
        method: 'HEAD',
        credentials: 'same-origin',
      });
      gatewayDetected = resp.headers.get('x-dsh-gateway') === '1';
    } catch {
      gatewayDetected = false;
    }
    return gatewayDetected;
  };

  ctx.inject(['workspaces'], (scope) => {
    const workspaces = scope.workspaces as {
      openPath?: (path: string) => Promise<unknown>;
    };
    const original = workspaces.openPath?.bind(workspaces);
    if (typeof original !== 'function') return;
    const wrapped = async (filePath: string) => {
      if (await isBehindGateway()) {
        // 经网关：下载到浏览器（路径由网关侧再做目录/敏感校验）
        const url = '/gateway/api/download?path=' + encodeURIComponent(filePath);
        window.location.assign(url);
        return { opened: true };
      }
      return original(filePath);
    };
    workspaces.openPath = wrapped;
    // ctx.inject 的回调返回值由 Cordis 作为 fiber disposer 收集；恢复共享服务，
    // 避免插件重载后包装层叠加或禁用插件后残留网关下载行为。
    return () => {
      if (workspaces.openPath === wrapped) workspaces.openPath = original;
    };
  });

  // 双语词典（zh/en）：卡片文字跟随 dsh 设置里的语言
  // （设置 → 通用 → 语言 / Settings → General → Language），切换即时生效
  ctx.effect(() => ctx.locale.register('dshpw', { zh, en }), 'dsh-passwords: dicts');
}
