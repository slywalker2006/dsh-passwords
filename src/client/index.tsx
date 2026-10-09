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


import { DshPasswordsCard } from './card';
import { DshPasswordsSection } from './section';
import { ChatLauncher } from './chat';
import { TokenReporter } from './token';
import { startPickerDelete } from './picker-delete';
import { startFileDownload } from './file-download';
import { zh, en } from './locales';

/** 卡片样式：全部使用 dsh 设计令牌（--dsw-alias-*），颜色/主题与官方 PluginCard 完全一致 */
const CSS = `
/* 共享缓动令牌（iOS 风格）：--dshpw-ease 柔和标准曲线（无回弹，面板/状态切换），
   --dshpw-spring 轻微过冲弹簧（开关、按钮、贴纸等可按压元素）。
   动画只动 transform/opacity/box-shadow（合成器线程，不掉帧），并尊重 prefers-reduced-motion。 */
.dshpw-card{--dshpw-ease:cubic-bezier(.22,1,.36,1);--dshpw-spring:cubic-bezier(.34,1.4,.64,1);--dshpw-accent:var(--dsw-alias-brand-primary,#14b8a6);--dshpw-ink:var(--dsw-alias-label-primary,#172026);--dshpw-inverted:var(--dsw-alias-label-primary-inverted,#fff);--dshpw-muted:var(--dsw-alias-label-tertiary,#74808a);--dshpw-line:var(--dsw-alias-border-l2,#e3e7e9);--dshpw-surface:var(--dsw-alias-bg-layer-2,#f8fafb);--dshpw-layer:var(--dsw-alias-bg-layer-3,#fff);--dshpw-success:var(--dsw-alias-state-success-primary,#10b981);--dshpw-warning:var(--dsw-alias-state-warn-primary,#f59e0b);--dshpw-danger:var(--dsw-alias-state-error-primary,#ef4444);display:flex;flex-direction:column;border:1px solid var(--dshpw-line);border-radius:14px;background:var(--dshpw-layer);box-shadow:0 8px 24px rgb(0 0 0 / 8%);transition:border-color .28s var(--dshpw-ease),box-shadow .28s var(--dshpw-ease);font-size:13px;line-height:1.5;overflow:hidden;color:var(--dshpw-ink);animation:dshpwCardIn .5s var(--dshpw-ease) both}
.dshpw-card:hover{border-color:color-mix(in srgb,var(--dshpw-accent) 35%,var(--dshpw-line));box-shadow:0 14px 34px rgb(0 0 0 / 13%)}
@keyframes dshpwCardIn{from{opacity:0;transform:translateY(14px) scale(.985)}to{opacity:1;transform:none}}
.dshpw-body{display:flex;flex-direction:column;gap:0;padding:10px 20px 24px}
/* 分区错落进场：transform 位移，不碰 layout/padding，避免页面跳动 */
.dshpw-body>.dshpw-section,.dshpw-body>.dshpw-profile{animation:dshpwSectionIn .48s var(--dshpw-ease) both}
.dshpw-body>.dshpw-profile{animation-delay:.02s}
.dshpw-body>.dshpw-section:nth-of-type(1){animation-delay:.05s}
.dshpw-body>.dshpw-section:nth-of-type(2){animation-delay:.09s}
.dshpw-body>.dshpw-section:nth-of-type(3){animation-delay:.13s}
.dshpw-body>.dshpw-section:nth-of-type(4){animation-delay:.17s}
.dshpw-body>.dshpw-section:nth-of-type(5){animation-delay:.21s}
.dshpw-body>.dshpw-section:nth-of-type(6){animation-delay:.25s}
.dshpw-body>.dshpw-section:nth-of-type(n+7){animation-delay:.29s}
@keyframes dshpwSectionIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
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
.dshpw-progress-fill{display:block;height:100%;border-radius:inherit;background:var(--dshpw-accent);transition:width .3s var(--dshpw-ease)}
.dshpw-progress-track.indeterminate .dshpw-progress-fill{width:38%;animation:dshpwProgress 1.1s ease-in-out infinite}
@keyframes dshpwProgress{from{transform:translateX(-110%)}to{transform:translateX(290%)}}
@media(max-width:640px){.dshpw-update-actions.has-progress{grid-template-columns:minmax(0,1fr) auto auto;gap:6px}.dshpw-update-inline-progress{min-width:0}.dshpw-update-inline-progress .dshpw-hint{display:none}.dshpw-update-apply{min-width:0}.dshpw-update-actions>.dshpw-btn{min-width:0;padding-inline:9px}.dshpw-update-manual-command{font-size:11px}}
.dshpw-form-actions{justify-content:flex-end}
.dshpw-preference{padding-top:14px}
.dshpw-profile{display:flex;align-items:center;gap:12px;padding:10px 0 18px;border-bottom:1px solid var(--dshpw-line)}
.dshpw-avatar{display:grid;place-items:center;width:38px;height:38px;border-radius:11px;background:var(--dshpw-accent);color:var(--dshpw-inverted);font-size:16px;font-weight:700;flex:none;box-shadow:0 2px 8px color-mix(in srgb,var(--dshpw-accent) 30%,transparent);animation:dshpwAvatarIn .5s var(--dshpw-spring) both}.dshpw-avatar-trigger{cursor:pointer;border:0;padding:0;appearance:none;font:inherit}.dshpw-avatar-trigger:focus-visible{outline:2px solid var(--dshpw-accent);outline-offset:3px}.dshpw-purge{margin:14px 0 0;padding:14px;border:1px solid var(--dshpw-danger);border-radius:10px;background:color-mix(in srgb,var(--dshpw-danger) 7%,transparent)}.dshpw-purge-warning{color:var(--dshpw-danger);font-weight:650}.dshpw-purge-actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.dshpw-purge .dshpw-check{color:var(--dshpw-danger)}
@keyframes dshpwAvatarIn{from{opacity:0;transform:scale(.6)}to{opacity:1;transform:none}}
.dshpw-profile-copy{display:flex;flex-direction:column;gap:1px;min-width:0}
.dshpw-profile-label{font-size:12px;color:var(--dshpw-muted)}
.dshpw-profile-copy strong{font-size:15px;line-height:1.3;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dshpw-signout{margin-left:auto}
.dshpw-status{display:inline-flex;align-items:center;gap:5px;padding:3px 9px;border-radius:999px;font-size:11px;font-weight:650;white-space:nowrap;animation:dshpwFadeSlideIn .3s var(--dshpw-ease) both}
.dshpw-status-neutral{background:color-mix(in srgb,var(--dshpw-muted) 12%,transparent);color:var(--dshpw-muted)}
.dshpw-status-success{background:color-mix(in srgb,var(--dshpw-success) 14%,transparent);color:var(--dshpw-success)}
.dshpw-status-warning{background:color-mix(in srgb,var(--dshpw-warning) 16%,transparent);color:var(--dshpw-warning)}
.dshpw-status-danger{background:color-mix(in srgb,var(--dshpw-danger) 14%,transparent);color:var(--dshpw-danger)}
.dshpw-update-status{display:inline-flex;align-items:center;gap:6px}
.dshpw-spinner{display:inline-block;width:12px;height:12px;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;animation:dshpwSpin .7s linear infinite;vertical-align:-2px}
@keyframes dshpwSpin{to{transform:rotate(360deg)}}
.dshpw-switch{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:13px 14px;border:1px solid var(--dshpw-line);border-radius:11px;background:var(--dshpw-surface);cursor:pointer;transition:border-color .24s var(--dshpw-ease),background .24s var(--dshpw-ease),transform .24s var(--dshpw-ease),box-shadow .24s var(--dshpw-ease)}
.dshpw-switch:hover{border-color:color-mix(in srgb,var(--dshpw-accent) 45%,var(--dshpw-line));background:var(--dshpw-layer);transform:translateY(-1px);box-shadow:0 4px 12px rgb(0 0 0 / 7%)}
.dshpw-switch:active{transform:translateY(0) scale(.995);box-shadow:none;transition-duration:.1s}
.dshpw-switch-copy{display:flex;flex-direction:column;gap:3px;min-width:0;color:var(--dshpw-ink)}
.dshpw-switch-copy strong{font-size:13px;font-weight:650;line-height:1.35}
.dshpw-switch-copy small{font-size:12px;line-height:1.4;color:var(--dshpw-muted)}
.dshpw-switch-control{position:relative;display:inline-flex;flex:0 0 auto;width:42px;height:24px}
.dshpw-switch-control input{position:absolute;width:1px;height:1px;opacity:0}
.dshpw-switch-track{position:absolute;inset:0;border-radius:999px;background:var(--dshpw-line);transition:background .28s var(--dshpw-ease),box-shadow .28s var(--dshpw-ease)}
.dshpw-switch-thumb{position:absolute;top:3px;left:3px;width:18px;height:18px;border-radius:50%;background:var(--dshpw-layer);box-shadow:0 1px 4px rgb(0 0 0 / 22%);transition:transform .28s var(--dshpw-spring)}
.dshpw-switch-control input:checked + .dshpw-switch-track{background:var(--dshpw-accent);box-shadow:0 0 0 3px color-mix(in srgb,var(--dshpw-accent) 15%,transparent)}
.dshpw-switch-control input:checked + .dshpw-switch-track .dshpw-switch-thumb{transform:translateX(18px)}
.dshpw-switch-control input:focus-visible + .dshpw-switch-track{outline:2px solid var(--dshpw-accent);outline-offset:3px}
.dshpw-input{width:100%;box-sizing:border-box;min-width:0;padding:9px 11px;font-size:13px;color:var(--dshpw-ink);background:var(--dshpw-surface);border:1px solid var(--dshpw-line);border-radius:9px;transition:border-color .22s var(--dshpw-ease),box-shadow .22s var(--dshpw-ease),background .22s var(--dshpw-ease)}
.dshpw-input:hover{border-color:color-mix(in srgb,var(--dshpw-ink) 32%,var(--dshpw-line));background:var(--dshpw-layer)}
.dshpw-input:focus{outline:none;border-color:var(--dshpw-accent);background:var(--dshpw-layer);box-shadow:0 0 0 3px color-mix(in srgb,var(--dshpw-accent) 16%,transparent)}
.dshpw-input::placeholder{color:var(--dshpw-muted)}
.dshpw-btn{appearance:none;border:1px solid transparent;border-radius:9px;padding:8px 14px;font-size:13px;line-height:1.35;font-weight:650;background:var(--dshpw-accent);color:var(--dshpw-inverted);cursor:pointer;white-space:nowrap;transition:background .22s var(--dshpw-ease),filter .22s var(--dshpw-ease),transform .12s var(--dshpw-ease),box-shadow .22s var(--dshpw-ease),opacity .22s var(--dshpw-ease)}
.dshpw-btn:hover:not(:disabled){filter:brightness(1.12);box-shadow:0 4px 12px rgb(0 0 0 / 12%);transform:translateY(-1px)}
.dshpw-btn:active:not(:disabled){transform:translateY(0) scale(.97);filter:brightness(.98);transition-duration:.08s}
.dshpw-btn:focus-visible{outline:2px solid var(--dshpw-accent);outline-offset:2px}
.dshpw-btn:disabled{opacity:.45;cursor:default;box-shadow:none}
.dshpw-btn.danger{background:transparent;border-color:var(--dshpw-danger);color:var(--dshpw-danger)}
.dshpw-btn.danger:hover:not(:disabled){filter:none;background:color-mix(in srgb,var(--dshpw-danger) 12%,transparent)}
.dshpw-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.dshpw-user{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--dshpw-line);animation:dshpwFadeSlideIn .32s var(--dshpw-ease) both}
.dshpw-user:last-child{border-bottom:none}
/* 权限块/工作区行/会话列表：进场 + 状态切换统一走柔和曲线（容器高度变化仅跟着 React 结构变，不做 layout 动画，避免卡顿） */
.dshpw-perm{border:1px solid var(--dshpw-line);border-radius:11px;padding:14px;display:flex;flex-direction:column;gap:10px;background:var(--dshpw-surface);animation:dshpwFadeSlideIn .36s var(--dshpw-ease) both}
.dshpw-perm-head{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.dshpw-workspaces{display:flex;flex-direction:column;gap:8px}
.dshpw-workspace{border:1px solid var(--dshpw-line);border-radius:9px;overflow:hidden;background:var(--dshpw-layer)}
.dshpw-workspace-switch{border:0;border-radius:0;background:transparent}
.dshpw-workspace-switch:hover{background:var(--dshpw-surface)}
.dshpw-session-list{display:flex;flex-direction:column;gap:6px;padding:10px 12px 12px 18px;border-top:1px solid var(--dshpw-line);animation:dshpwFadeSlideIn .28s var(--dshpw-ease) both}
.dshpw-session-check{display:flex;align-items:center;gap:8px;font-size:12px;color:var(--dshpw-muted);cursor:pointer;min-height:28px;border-radius:6px;transition:background .18s var(--dshpw-ease),color .18s var(--dshpw-ease)}
.dshpw-session-check:hover{background:color-mix(in srgb,var(--dshpw-accent) 6%,transparent);color:var(--dshpw-ink)}
.dshpw-session-check input,.dshpw-check input{accent-color:var(--dshpw-accent);cursor:pointer}
.dshpw-session-check span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dshpw-check{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--dshpw-muted);cursor:pointer;border-radius:6px;transition:color .18s var(--dshpw-ease)}
.dshpw-check:hover{color:var(--dshpw-ink)}
.dshpw-check span{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dshpw-check small{font-size:11px;color:var(--dshpw-muted);opacity:.8}
.dshpw-check input:disabled{cursor:not-allowed}
/* 模型 allowlist：可滚动的多选清单（目录可能很长）*/
.dshpw-model-list{display:flex;flex-direction:column;gap:4px;max-height:220px;overflow-y:auto;padding:8px 10px;border:1px solid var(--dshpw-line);border-radius:9px;background:var(--dshpw-layer);animation:dshpwFadeSlideIn .28s var(--dshpw-ease) both;scrollbar-width:thin}
.dshpw-model-list .dshpw-check{min-height:26px}
select.dshpw-input{height:auto;min-height:38px;cursor:pointer}
.dshpw-badge{font-size:11px;padding:3px 8px;border-radius:999px;border:1px solid color-mix(in srgb,var(--dshpw-accent) 45%,transparent);color:var(--dshpw-success);background:color-mix(in srgb,var(--dshpw-success) 14%,transparent);margin-left:6px;white-space:nowrap;animation:dshpwFadeSlideIn .28s var(--dshpw-ease) both}
.dshpw-badge.admin{border-color:color-mix(in srgb,var(--dshpw-warning) 55%,transparent);color:var(--dshpw-warning);background:color-mix(in srgb,var(--dshpw-warning) 16%,transparent)}
.dshpw-error{color:var(--dshpw-danger);font-size:12px;animation:dshpwShakeIn .4s var(--dshpw-ease) both}
.dshpw-ok{color:var(--dshpw-success);font-size:12px;animation:dshpwFadeSlideIn .3s var(--dshpw-ease) both}
.dshpw-hint{font-size:12px;line-height:1.5;color:var(--dshpw-muted)}
.dshpw-empty-state{display:flex;align-items:center;justify-content:center;padding:24px 12px;color:var(--dshpw-muted);font-size:12px;animation:dshpwFadeSlideIn .3s var(--dshpw-ease) both}
.dshpw-perms-content{display:flex;flex-direction:column;gap:12px;min-width:0}
@keyframes dshpwFadeSlideIn{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:none}}
@keyframes dshpwShakeIn{0%{opacity:0;transform:translateX(0)}20%{opacity:1;transform:translateX(-4px)}40%{transform:translateX(4px)}60%{transform:translateX(-2px)}80%{transform:translateX(2px)}100%{transform:translateX(0)}}
@media (prefers-reduced-motion:reduce){.dshpw-card,.dshpw-body>.dshpw-section,.dshpw-body>.dshpw-profile,.dshpw-avatar,.dshpw-status,.dshpw-user,.dshpw-perm,.dshpw-session-list,.dshpw-model-list,.dshpw-badge,.dshpw-error,.dshpw-ok,.dshpw-empty-state,.dshpw-btn,.dshpw-switch,.dshpw-switch-track,.dshpw-switch-thumb,.dshpw-input,.dshpw-progress-fill,.dshpw-session-check,.dshpw-check,.dshpw-spinner{transition:none!important;animation:none!important}}
@media (max-width:560px){.dshpw-body{padding:6px 14px 18px}.dshpw-section{padding:16px 0}.dshpw-action-row{align-items:stretch}.dshpw-action-row .dshpw-btn{width:100%}.dshpw-patch-actions .dshpw-btn{width:100%}.dshpw-signout{width:auto!important}.dshpw-section-head{align-items:flex-start;flex-direction:column;gap:7px}.dshpw-status{max-width:100%;white-space:normal}.dshpw-profile{align-items:flex-start}.dshpw-profile .dshpw-signout{margin-left:auto}}
/* 可读取目录：只读 chips + 固定高度目录浏览器 */
.dshpw-read-folders{display:flex;flex-direction:column;gap:8px;min-width:0}
.dshpw-read-folders .dshpw-btn{border-radius:8px}
.dshpw-chip-row{display:flex;flex-wrap:wrap;gap:6px;min-width:0}
.dshpw-chip{display:inline-flex;align-items:center;gap:6px;max-width:100%;padding:3px 4px 3px 10px;border:1px solid var(--dshpw-line);border-radius:8px;background:var(--dshpw-layer);font-size:12px;color:var(--dshpw-ink)}
.dshpw-chip-path{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dshpw-chip-remove{display:inline-flex;align-items:center;justify-content:center;width:20px;height:20px;flex:none;padding:0;border:0;border-radius:6px;background:transparent;color:var(--dshpw-muted);cursor:pointer;transition:background .18s var(--dshpw-ease),color .18s var(--dshpw-ease)}
.dshpw-chip-remove:hover:not(:disabled){background:color-mix(in srgb,var(--dshpw-danger) 12%,transparent);color:var(--dshpw-danger)}
.dshpw-chip-remove:disabled{cursor:default;opacity:.45}
.dshpw-dir-icon{width:14px;height:14px;flex:none}
.dshpw-dir-picker{display:flex;flex-direction:column;gap:8px;height:320px;box-sizing:border-box;padding:10px 12px;border:1px solid var(--dshpw-line);border-radius:8px;background:var(--dshpw-layer);animation:dshpwFadeSlideIn .28s var(--dshpw-ease) both}
.dshpw-dir-picker-head{display:flex;align-items:center;gap:6px;min-width:0}
.dshpw-dir-picker-crumbs{display:flex;align-items:center;gap:2px;flex:1;min-width:0;overflow-x:auto;white-space:nowrap;scrollbar-width:thin}
.dshpw-dir-picker-seg{display:inline-flex;align-items:center;flex:none}
.dshpw-dir-picker-sep{color:var(--dshpw-muted);margin:0 2px}
.dshpw-dir-picker-current{font-size:12px;color:var(--dshpw-ink);overflow:hidden;text-overflow:ellipsis}
.dshpw-dir-picker-crumb{appearance:none;border:0;background:transparent;color:var(--dshpw-accent);font-size:12px;padding:0 4px;border-radius:6px;cursor:pointer;white-space:nowrap}
.dshpw-dir-picker-crumb:hover:not(:disabled){background:color-mix(in srgb,var(--dshpw-accent) 10%,transparent)}
.dshpw-dir-picker-crumb:disabled{cursor:default;opacity:.5}
.dshpw-dir-picker-tool{display:inline-flex;align-items:center;justify-content:center;width:26px;height:26px;flex:none;padding:0;border:1px solid var(--dshpw-line);border-radius:8px;background:var(--dshpw-surface);color:var(--dshpw-muted);cursor:pointer;transition:background .18s var(--dshpw-ease),color .18s var(--dshpw-ease),border-color .18s var(--dshpw-ease)}
.dshpw-dir-picker-tool:hover:not(:disabled){border-color:color-mix(in srgb,var(--dshpw-accent) 45%,var(--dshpw-line));color:var(--dshpw-ink)}
.dshpw-dir-picker-tool:disabled{cursor:default;opacity:.45}
.dshpw-dir-picker-select-current{align-self:flex-start}
.dshpw-dir-picker-body{flex:1;min-height:0;display:flex;flex-direction:column;gap:6px;overflow-y:auto;scrollbar-width:thin}
.dshpw-dir-picker-list{display:flex;flex-direction:column}
.dshpw-dir-picker-row{display:flex;align-items:center;justify-content:space-between;gap:8px;height:32px;min-height:32px;padding:0 4px;border-radius:6px}
.dshpw-dir-picker-row:hover{background:color-mix(in srgb,var(--dshpw-accent) 6%,transparent)}
.dshpw-dir-picker-name{flex:1;min-width:0;font-size:12px;color:var(--dshpw-ink);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dshpw-dir-picker-actions{display:inline-flex;gap:6px;flex:none}
.dshpw-dir-picker-actions .dshpw-btn,.dshpw-dir-picker-select-current{border-radius:8px;padding:4px 10px;font-size:12px}
`;

export const inject = ['slots', 'locale'] as const;

export function apply(ctx: ClientContext): void {
  // 目录选择器删除按钮（仅主用户）：角色由模块内部探测，非主用户零副作用；
  // 授权由网关 requireAdmin 兜底。这里 fire-and-forget，不阻塞插件加载。
  startPickerDelete();

  // 右侧栏文件下载按钮（主用户/已授权子用户）：权限由模块内部探测（fail-closed），
  // 授权由网关下载端点兜底。同样 fire-and-forget。
  startFileDownload();

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
