// dsh-passwords 设置卡片：内容平铺展示（独立 settings.section 分区，不再折叠）。
// 内容：
//   - 当前身份（账号 + 角色徽章）
//   - 远程设置补丁：状态（所有用户可见）+ "重载补丁"按钮（仅主用户；F-02）
//   - 用户管理：改密/改名/子用户分配（主用户 admin 可管理所有，子用户只能改自己）
// 数据面：/api/dsh-passwords/*（网关注入的 JWT cookie 鉴权）。
//
// 语言：卡片词典注册在 locale 命名空间 'dshpw'（见 locales.ts），文字跟随
// dsh 设置里的语言（Settings → General → Language）。t seat 由注册时的
// `locale: 'dshpw'` 声明注入。
import { createElement as h, useEffect, useRef, useState } from 'react';
import type { PropsLocale } from '@deepseek-ai/dsh-client-ui-slots';
import { publishChatEntryChanged } from './events';
import { api } from './api';

export interface UserInfo {
  id: number;
  username: string;
  role: 'admin' | 'user';
  created_at: string;
  last_login_at: string | null;
}

export interface StateData {
  me: { username: string; role: 'admin' | 'user' };
  users: UserInfo[];
  /** 当前账号的聊天入口显示偏好；旧服务端未返回时默认开启。 */
  chatEnabled?: boolean;
}

export interface PatchState {
  settingsHostMode: boolean;
  whitelist: boolean;
  workspaceSearch: boolean;
  bindAll: boolean;
  connectionCookieBridge: 'patched' | 'native' | 'missing' | 'unsupported';
}

export function readPatchState(response: unknown): PatchState | null {
  if (typeof response !== 'object' || response === null || !('status' in response)) return null;
  const status = response.status;
  if (typeof status !== 'object' || status === null ||
    !('settingsHostMode' in status) || typeof status.settingsHostMode !== 'boolean' ||
    !('whitelist' in status) || typeof status.whitelist !== 'boolean' ||
    !('workspaceSearch' in status) || typeof status.workspaceSearch !== 'boolean' ||
    !('bindAll' in status) || typeof status.bindAll !== 'boolean' ||
    !('connectionCookieBridge' in status) ||
    (status.connectionCookieBridge !== 'patched' && status.connectionCookieBridge !== 'native' &&
      status.connectionCookieBridge !== 'missing' && status.connectionCookieBridge !== 'unsupported')) return null;
  return {
    settingsHostMode: status.settingsHostMode,
    whitelist: status.whitelist,
    workspaceSearch: status.workspaceSearch,
    bindAll: status.bindAll,
    connectionCookieBridge: status.connectionCookieBridge,
  };
}

/** /api/dsh-passwords/update/status 的返回（与网关 UpdateStatus 镜像） */
export interface UpdateInfo {
  env: 'docker' | 'git' | 'npm-global' | 'npm-prefix' | 'unknown';
  currentVersion: string;
  latestVersion: string | null;
  updateAvailable: boolean;
  phase: 'idle' | 'downloading' | 'ready' | 'installing' | 'restarting' | 'error';
  downloadPercent: number | null;
  downloadMode: 'automatic' | 'manual' | null;
  downloadedBytes: number;
  totalBytes: number | null;
  pendingVersion: string | null;
  installConfirmationRequired: boolean;
  lastNotificationAt: string | null;
  idleRemainingMs: number | null;
  autoUpdateEnabled: boolean;
  autoInstallSupported: boolean;
  checking: boolean;
  manualCommand: string;
  lastCheckedAt: string | null;
  lastError: string | null;
  applyCooldownRemainingMs: number;
}


export interface PermOverview {
  me: { id: number; username: string; role: 'admin' | 'user' };
  availableWebSocketPaths: string[];
  users: Array<{
    id: number;
    username: string;
    role: 'admin' | 'user';
    permissions: {
      allowedFolders: string[];
      hourlyTokenLimit: number | null;
      dailyMinutesLimit: number | null;
      allowUpload: boolean;
      allowGitDownload: boolean;
      allowWorkspaceCreate: boolean;
      allowSsh?: boolean;
      allowedWebSocketPaths: string[];
      allowedAgentPresets: string[] | null;
      banned: boolean;
      sandboxMode: string | null;
      disabledSessions: string[];
      allowedSessionIds: string[];
    };
    usage: {
      day: string;
      activeSeconds: number;
      hourlyTokens: number;
      firstSeenAt: string | null;
      lastActiveAt: string | null;
    } | null;
  }>;
}

interface PermDraft {
  folders: string[];
  token: string;
  minutes: string;
  upload: boolean;
  git: boolean;
  workspaceCreate: boolean;
  ssh: boolean;
  banned: boolean;
  sandbox: string;
  disabledSessions: string[];
  allowedSessionIds: string[];
  webSocketPaths: string[];
  agentPresets: string[] | null;
}

interface AgentPresetInfo {
  id: string;
  trust: 'system' | 'user';
  isDefault: boolean;
  name?: string;
  description?: string;
  broken?: string;
}

interface WorkspaceInfo {
  path: string;
  title: string;
  sessions: Array<{ id: string; title: string }>;
}

/** 与 host 侧一致的最小密码策略（本机提示用，最终以服务端校验为准） */
const PASSWORD_RE = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,}$/;
const USERNAME_RE = /^[A-Za-z0-9_-]{3,32}$/;

/**
 * 严格非负整数解析（限额输入用）：
 *   空串 → null（=不限）；纯数字 → 整数；其余（1e3/0x10/12.5/-1/超大值）→ NaN（非法）。
 * 之前用 Number('1e3')=1000 / Number('0x10')=16 会静默接受科学计数与十六进制。
 * Number.isSafeInteger 同时封顶 2^53-1，低于 SQLite 64 位上限，防精度失真。
 */
export function parseLimit(raw: string): number | null {
  const t = raw.trim();
  if (t === '') return null;
  if (!/^\d+$/.test(t)) return Number.NaN;
  const n = Number(t);
  return Number.isSafeInteger(n) ? n : Number.NaN;
}

/** 本地时间格式化（ISO → 可读的 YYYY-MM-DD HH:mm） */
function fmtTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

type StatusTone = 'neutral' | 'success' | 'warning' | 'danger';

function StatusPill(props: { tone?: StatusTone; children?: React.ReactNode }) {
  return h('span', { className: `dshpw-status dshpw-status-${props.tone ?? 'neutral'}` }, props.children);
}

function SectionHeader(props: { label: React.ReactNode; status?: React.ReactNode; tone?: StatusTone }) {
  return h(
    'div',
    { className: 'dshpw-section-head' },
    h('div', { className: 'dshpw-section-title' }, h('span', { className: 'dshpw-label' }, props.label)),
    props.status === undefined ? null : h(StatusPill, { tone: props.tone, children: props.status }),
  );
}

/** 错误文案：有 code 走本地词典，未知 code / 无 code 回退服务端文案。
 *  词典项含占位符（{minutes}/{count} 等）时客户端无参数可填，回退服务端已插值文案。 */
function errText(error: unknown, tr: (key: string, params?: Record<string, string | number>) => string): string {
  if (error instanceof Error) {
    const code = (error as Error & { code?: string }).code;
    if (code) {
      const key = `err.${code}`;
      const localized = tr(key);
      if (localized !== key && !localized.includes('{')) return localized;
    }
    return error.message;
  }
  return tr('opFailed');
}

export function DshPasswordsCard(props: PropsLocale<'dshpw'>) {
  const t = props.t;
  // errText 需要接收动态 key（err.<code>），而 dshpw 词典 t 的 key 是受限联合类型：
  // 这里包一层宽松签名适配器（运行时行为不变）
  const trErr = (key: string, params?: Record<string, string | number>) => t(key as never, params);

  const [data, setData] = useState<StateData | null>(null);
  const [patchState, setPatchState] = useState<PatchState | null>(null);
  const [updateInfo, setUpdateInfo] = useState<UpdateInfo | null>(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [updateBusy, setUpdateBusy] = useState(false);
  const [updateChecking, setUpdateChecking] = useState(false);
  const [signOutBusy, setSignOutBusy] = useState(false);

  // 改密表单
  const [pwTarget, setPwTarget] = useState('');
  // F-06：自助改密需验证当前密码（主用户重置他人时无需）
  const [pwCurrent, setPwCurrent] = useState('');
  const [pwNew, setPwNew] = useState('');
  const [pwConfirm, setPwConfirm] = useState('');
  // 改名表单
  const [nameTarget, setNameTarget] = useState('');
  const [nameNew, setNameNew] = useState('');
  // 新增子用户表单
  const [addName, setAddName] = useState('');
  const [addPw, setAddPw] = useState('');
  // 权限管理（仅主用户）
  const [overview, setOverview] = useState<PermOverview | null>(null);
  const [permDrafts, setPermDrafts] = useState<Record<number, PermDraft>>({});
  const [agentPresets, setAgentPresets] = useState<AgentPresetInfo[]>([]);
  const [agentPresetStatus, setAgentPresetStatus] = useState<'loading' | 'ready' | 'unavailable'>('loading');

  const [workspaces, setWorkspaces] = useState<WorkspaceInfo[]>([]);
  // 正在编辑中的子用户草稿：dirty 时 30s 自动刷新不覆盖本地未保存的修改
  const dirtyUsersRef = useRef<Set<number>>(new Set());
  // 刷新 in-flight 守卫：慢网络下 30s 定时 + 操作后手动 refresh 不重叠。
  // 若刷新期间又有请求，排队在当前响应结束后补跑，避免旧快照覆盖乐观分配结果。
  const refreshingRef = useRef(false);
  const refreshQueuedRef = useRef(false);

  const refresh = () => {
    if (refreshingRef.current) {
      refreshQueuedRef.current = true;
      return;
    }
    refreshingRef.current = true;
    // in-flight 守卫覆盖整个 state→overview→workspaces 链（而非只覆盖 patch/status）：
    // 否则慢网络下 overview 未返回时守卫已被 patch/status 提前释放，30s 定时又会叠一轮。
    api<StateData>('/api/dsh-passwords/state')
      .then((d) => {
        setData(d);
        setError('');
        if (d.me?.role !== 'admin') return undefined;
        return api<PermOverview>('/gateway/api/overview')
          .then((o) => {
            setOverview(o);
            // 草稿同步：新用户初始化；未在编辑（dirty）中的草稿用服务端最新值覆盖
            // （注释承诺的“主用户在别处修改后页面自动同步最新状态”真正生效）；
            // 已删除的用户清草稿；正在编辑的用户保留本地未保存修改。
            setPermDrafts((prev) => {
              const drafts: Record<number, PermDraft> = { ...prev };
              const live = new Set<number>();
              for (const u of o.users) {
                if (u.role !== 'user') continue;
                live.add(u.id);
                const fresh: PermDraft = {
                  folders: [...(u.permissions.allowedFolders ?? [])],
                  token: u.permissions.hourlyTokenLimit === null ? '' : String(u.permissions.hourlyTokenLimit),
                  minutes: u.permissions.dailyMinutesLimit === null ? '' : String(u.permissions.dailyMinutesLimit),
                  upload: u.permissions.allowUpload,
                  git: u.permissions.allowGitDownload,
                  workspaceCreate: u.permissions.allowWorkspaceCreate,
                  ssh: u.permissions.allowSsh === true,
                  banned: u.permissions.banned,
                  webSocketPaths: [...(u.permissions.allowedWebSocketPaths ?? [])],
                  agentPresets: u.permissions.allowedAgentPresets === null ? null : [...u.permissions.allowedAgentPresets],
                  sandbox: u.permissions.sandboxMode ?? '',
                  disabledSessions: [...(u.permissions.disabledSessions ?? [])],
                  allowedSessionIds: [...(u.permissions.allowedSessionIds ?? [])],
                };
                if (!(u.id in drafts) || !dirtyUsersRef.current.has(u.id)) {
                  drafts[u.id] = fresh;
                }
              }
              for (const id of Object.keys(drafts)) {
                if (!live.has(Number(id))) delete drafts[Number(id)];
              }
              return drafts;
            });
            return Promise.allSettled([
              api<{ workspaces: WorkspaceInfo[] }>('/api/dsh-passwords/workspaces'),
              api<{ presets: AgentPresetInfo[] }>('/api/dsh-passwords/agent-presets'),
            ])
              .then(([workspaceResult, presetResult]) => {
                if (refreshQueuedRef.current) return;

                if (workspaceResult.status === 'fulfilled') {
                  setWorkspaces(workspaceResult.value.workspaces ?? []);
                }

                if (presetResult.status === 'fulfilled') {
                  setAgentPresets(presetResult.value.presets ?? []);
                  setAgentPresetStatus('ready');
                } else {
                  setAgentPresets([]);
                  setAgentPresetStatus('unavailable');
                }
              })
              .then(() => undefined)
              .catch((e) => {
                // 工作区清单是权限编辑的可信状态；请求失败不能用空数组覆盖，
                // 否则页面会把所有工作区误显示为关闭并在下一次保存时丢权限。
                if (!refreshQueuedRef.current) {
                  setError(errText(e, trErr));
                }
              });
          })
          .catch(() => setOverview(null));
      })
      .catch((e) => setError(errText(e, trErr)))
      .finally(() => {
        refreshingRef.current = false;
        if (refreshQueuedRef.current) {
          refreshQueuedRef.current = false;
          refresh();
        }
      });
    // patch 状态独立于主链（轻量 + 失败只影响状态展示）
    api<unknown>('/api/dsh-passwords/patch/status')
      .then((r) => setPatchState(readPatchState(r)))
      .catch(() => setPatchState(null));
    // 更新状态独立拉取（失败只降级为状态未知，不阻塞主链）
    api<{ ok?: boolean; status?: UpdateInfo }>('/api/dsh-passwords/update/status')
      .then((r) => setUpdateInfo(r.status ?? null))
      .catch(() => setUpdateInfo(null));
  };

  // 密码门已是独立设置分区页（settings.section），无需折叠：
  // 进入分区即渲染全部内容，并每 30 秒自动刷新（主用户在别处修改子用户
  // 权限/工作区后，页面自动同步最新状态）
  useEffect(() => {
    refresh();
    const timer = window.setInterval(refresh, 30_000);
    return () => window.clearInterval(timer);
  }, []);

  // 后台自动下载不经过“立即检查/立即安装”按钮，下载进度也必须在设置页
  // 实时可见；只轮询轻量 update/status，不重复拉取用户、权限和工作区数据。
  useEffect(() => {
    const phase = updateInfo?.phase;
    const active = updateInfo?.checking || phase === 'downloading' || phase === 'installing' || phase === 'restarting'
      || (updateInfo?.autoUpdateEnabled === true && updateInfo.updateAvailable && phase === 'idle');
    if (!active) return undefined;
    const poll = () => {
      api<{ ok?: boolean; status?: UpdateInfo }>('/api/dsh-passwords/update/status')
        .then((r) => {
          if (r.status) setUpdateInfo(r.status);
        })
        .catch(() => undefined);
    };
    poll();
    const timer = window.setInterval(poll, 700);
    return () => window.clearInterval(timer);
  }, [updateInfo?.checking, updateInfo?.phase, updateInfo?.autoUpdateEnabled, updateInfo?.updateAvailable]);

  const isAdmin = data?.me?.role === 'admin';
  const me = data?.me?.username ?? '';
  const chatEnabled = data?.chatEnabled ?? true;

  const run = async (
    fn: () => Promise<unknown>,
    okMessage: string,
    afterSuccess?: () => Promise<void>,
  ) => {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const result = await fn();
      const customNotice =
        result !== null && typeof result === 'object' && 'notice' in result && typeof result.notice === 'string'
          ? result.notice
          : null;
      setNotice(customNotice ?? okMessage);
      if (afterSuccess) {
        await afterSuccess();
        return;
      }
      refresh();
    } catch (e) {
      setError(errText(e, trErr));
    } finally {
      setBusy(false);
    }
  };

  /** 重载补丁（仅主用户）：发送请求后轮询网关恢复，不固定等待 6 秒。 */
  const reloadPatch = () => {
    void run(
      () => api('/api/dsh-passwords/patch/reload', {}),
      t('reloading'),
      async () => {
        // 给 apply + 服务重启一个最短启动窗口；之后每 400ms 探测一次，
        // 服务恢复即刷新，网络慢时不会过早刷新到旧页面，也不会固定卡 6 秒。
        await new Promise((resolve) => window.setTimeout(resolve, 1800));
        const deadline = Date.now() + 30_000;
        while (Date.now() < deadline) {
          try {
            // 探测真实 dsh 上游页面而非网关自有 overview：只有网页服务恢复，
            // 这里才会返回成功，避免网关本身仍在但 dsh 还没重启完就刷新旧插件。
            const response = await fetch(`/?reload=${String(Date.now())}`, {
              cache: 'no-store',
              credentials: 'same-origin',
            });
            if (response.ok) {
              window.location.reload();
              return;
            }
          } catch {
            // dsh 网页服务重启窗口：继续探测
          }
          await new Promise((resolve) => window.setTimeout(resolve, 400));
        }
        throw new Error(t('patchReloadTimeout'));
      },
    );
  };

  /** 立即检查更新（仅主用户）：检查期间只锁定更新区，并轮询真实状态。 */
  const checkUpdate = async () => {
    if (updateBusy) return;
    setUpdateBusy(true);
    setUpdateChecking(true);
    setError('');
    setNotice('');
    try {
      await api('/api/dsh-passwords/update/check', {});
      const deadline = Date.now() + 60_000;
      while (Date.now() < deadline) {
        const response = await api<{ status?: UpdateInfo }>('/api/dsh-passwords/update/status');
        const status = response.status;
        if (status) {
          setUpdateInfo(status);
          if (!status.checking) break;
        }
        await new Promise((resolve) => window.setTimeout(resolve, 700));
      }
      setNotice(t('updateCheckStarted'));
    } catch (e) {
      setError(errText(e, trErr));
    } finally {
      setUpdateChecking(false);
      setUpdateBusy(false);
    }
  };

  /** 主用户更新操作：首次手动操作启动下载，已就绪时才安装。 */
  const applyUpdate = async () => {
    if (updateBusy) return;
    setUpdateBusy(true);
    setError('');
    setNotice('');
    try {
      const result = await api<{ ok?: boolean; code?: string; message?: string; error?: string; requiresManualRestart?: boolean; phase?: UpdateInfo['phase'] }>('/api/dsh-passwords/update/apply', {});
      const inProgress = result.code === 'DOWNLOAD_IN_PROGRESS' || result.code === 'INSTALL_STARTED' || result.code === 'INSTALL_IN_PROGRESS';
      if (result.ok === false && !inProgress) throw new Error(result.message || result.error || t('updateApplyFailed'));
      if (result.code === 'DOWNLOAD_STARTED') {
        // 立即进入 indeterminate 状态，避免小包在首轮轮询前完成而没有任何视觉反馈。
        setUpdateInfo((current) => current ? { ...current, phase: 'downloading', downloadPercent: null, downloadMode: 'manual' } : current);
      } else if (result.code === 'INSTALL_STARTED') {
        // Compose 更新会在后台执行，先显示进行中状态，避免点击后无反馈。
        setUpdateInfo((current) => current ? { ...current, phase: 'installing', downloadPercent: null } : current);
      }
      setNotice(result.code === 'DOWNLOAD_STARTED' ? t('updateDownloadStarted') : inProgress ? (result.message || t('updateApplyStarted')) : result.requiresManualRestart ? t('updateManualRestart') : t('updateApplyStarted'));
      const deadline = Date.now() + 30 * 60_000;
      while (Date.now() < deadline) {
        const response = await api<{ status?: UpdateInfo }>('/api/dsh-passwords/update/status');
        const status = response.status;
        if (status) {
          setUpdateInfo(status);
          if (status.phase !== 'downloading' && status.phase !== 'installing' && status.phase !== 'restarting') break;
        }
        await new Promise((resolve) => window.setTimeout(resolve, 700));
      }
    } catch (e) {
      setError(errText(e, trErr));
    } finally {
      setUpdateBusy(false);
    }
  };

  /** 持久化自动更新开关；部署级强制关闭时以后端返回的实际状态为准。 */
  const toggleAutoUpdate = async () => {
    if (updateBusy) return;
    const enabled = !(updateInfo?.autoUpdateEnabled ?? true);
    setUpdateBusy(true);
    setError('');
    setNotice('');
    try {
      const response = await api<{ status?: UpdateInfo }>('/api/dsh-passwords/update/auto', { enabled });
      setNotice(t('updateToggleSaved'));
      if (response.status) setUpdateInfo(response.status);
    } catch (e) {
      setError(errText(e, trErr));
    } finally {
      setUpdateBusy(false);
    }
  };

  /** 登出成功/失败都回到登录页；失败通常意味着会话已经失效。 */
  const signOut = () => {
    if (signOutBusy) return;
    setSignOutBusy(true);
    fetch('/gateway/logout', { method: 'POST', credentials: 'same-origin' })
      .catch(() => undefined)
      .finally(() => window.location.assign('/gateway/login'));
  };

  /** 空闲窗剩余毫秒 → 模板需要的分钟数 */
  const idleMinutes = (ms: number): string => String(Math.max(1, Math.ceil(ms / 60000)));

  /** 聊天入口按账号跨设备同步；保存成功后立即通知 overlay，无需刷新页面。 */
  const toggleChatEntry = () => {
    const enabled = !chatEnabled;
    void run(
      () => api('/api/dsh-passwords/chat-enabled', { enabled }),
      t('chatToggleSaved'),
      async () => {
        publishChatEntryChanged(enabled);
        setData((prev) => (prev ? { ...prev, chatEnabled: enabled } : prev));
      },
    );
  };

  const changePassword = () => {
    if (pwNew !== pwConfirm) return setError(t('pwMismatch'));
    if (!PASSWORD_RE.test(pwNew)) return setError(t('pwPolicy'));
    const target = pwTarget || me;
    const isSelf = target === me;
    // F-06：改自己必须填当前密码（服务端也会校验，这里前端先拦空值）
    if (isSelf && pwCurrent === '') return setError(t('needCurrentPw'));
    void run(
      () =>
        api('/api/dsh-passwords/password', {
          target,
          password: pwNew,
          ...(isSelf ? { currentPassword: pwCurrent } : {}),
        }),
      t('pwChanged'),
    );
  };

  const rename = () => {
    if (!USERNAME_RE.test(nameNew)) return setError(t('namePolicy'));
    const target = nameTarget || me;
    const isSelf = target === me;
    void run(
      () => api('/api/dsh-passwords/username', { target, username: nameNew }),
      isSelf ? t('nameChangedSelf') : t('nameChanged'),
      isSelf
        ? async () => {
            // 改名后旧 JWT 已按 credential_version 失效：主动 POST logout 清理服务端
            // 吊销状态，再跳登录页；即使注销请求因重启/网络失败，也必须跳走，
            // 避免用户停留在一个注定失效的设置页。
            await fetch('/gateway/logout', { method: 'POST', credentials: 'same-origin' }).catch(() => undefined);
            window.location.assign('/gateway/login');
          }
        : undefined,
    );
  };

  const addSubUser = () => {
    if (!USERNAME_RE.test(addName)) return setError(t('namePolicy'));
    if (!PASSWORD_RE.test(addPw)) return setError(t('pwPolicy'));
    void run(() => api('/api/dsh-passwords/users', { username: addName, password: addPw }), t('subCreated'));
  };

  const removeUser = (username: string) => {
    if (!window.confirm(t('delConfirm', { username }))) return;
    void run(() => api('/api/dsh-passwords/users/remove', { target: username }), t('deleted'));
  };

  // 权限草稿更新 + 保存（仅主用户）
  const setDraft = (userId: number, patch: Partial<PermDraft>) => {
    dirtyUsersRef.current.add(userId);
    setPermDrafts((prev) => ({ ...prev, [userId]: { ...prev[userId], ...patch } }));
  };

  const enabledFolderSet = (draft: PermDraft): Set<string> => {
    if (draft.folders.includes('__deny__')) return new Set();
    if (draft.folders.length === 0) return new Set(workspaces.map((workspace) => workspace.path));
    return new Set(draft.folders);
  };

  const toggleWorkspace = (userId: number, workspace: WorkspaceInfo, enabled: boolean) => {
    const draft = permDrafts[userId];
    if (!draft) return;
    const enabledFolders = enabledFolderSet(draft);
    if (enabled) enabledFolders.add(workspace.path);
    else enabledFolders.delete(workspace.path);
    setDraft(userId, {
      folders: enabledFolders.size === 0 ? ['__deny__'] : [...enabledFolders],
    });
  };

  const toggleSession = (userId: number, sessionId: string, enabled: boolean) => {
    const draft = permDrafts[userId];
    if (!draft) return;
    const allowed = new Set(draft.allowedSessionIds);
    const disabled = new Set(draft.disabledSessions);
    if (enabled) {
      allowed.add(sessionId);
      disabled.delete(sessionId);
    } else {
      allowed.delete(sessionId);
      disabled.add(sessionId);
    }
    setDraft(userId, { allowedSessionIds: [...allowed], disabledSessions: [...disabled] });
  };

  const savePermissions = (userId: number) => {
    const d = permDrafts[userId];
    if (!d) return;
    // 非法输入不能静默转 null（=不限）：parseLimit 拒绝小数/负数/科学计数/十六进制/超大值
    const tokenNum = parseLimit(d.token);
    const minutesNum = parseLimit(d.minutes);
    if (tokenNum !== null && !Number.isInteger(tokenNum)) {
      setError(t('err.INVALID'));
      return;
    }
    if (minutesNum !== null && !Number.isInteger(minutesNum)) {
      setError(t('err.INVALID'));
      return;
    }
    void run(
      () =>
        api<{
          allowedFolders?: string[];
          allowedSessionIds?: string[];
          disabledSessions?: string[];
        }>('/gateway/api/permissions', {
          userId,
          allowedFolders: d.folders,
          hourlyTokenLimit: tokenNum,
          dailyMinutesLimit: minutesNum,
          allowUpload: d.upload,
          allowGitDownload: d.git,
          allowWorkspaceCreate: d.workspaceCreate,
          allowSsh: d.ssh,
          allowedWebSocketPaths: d.webSocketPaths,
          allowedAgentPresets: d.agentPresets,
          banned: d.banned,
          sandboxMode: d.sandbox === '' ? null : d.sandbox,
          disabledSessions: d.disabledSessions,
          allowedSessionIds: d.allowedSessionIds,
        }).then((saved: { allowedFolders?: string[]; allowedSessionIds?: string[]; disabledSessions?: string[] }) => {
          // 先采用服务端规范化结果，再执行刷新；避免保存成功后短暂显示旧草稿。
          setPermDrafts((prev) => {
            const current = prev[userId];
            if (!current) return prev;
            return {
              ...prev,
              [userId]: {
                ...current,
                folders: saved.allowedFolders ?? current.folders,
                allowedSessionIds: saved.allowedSessionIds ?? current.allowedSessionIds,
                disabledSessions: saved.disabledSessions ?? current.disabledSessions,
              },
            };
          });
          dirtyUsersRef.current.delete(userId);
        }),
      t('permsSaved'),
    );
  };


  // 管理员的目标用户下拉：列出全部用户（默认自己，即当前账号在列表中的那一项）
  const targetSelect = (value: string, onChange: (v: string) => void) =>
    isAdmin
      ? h(
          'select',
          {
            className: 'dshpw-input',
            value: value || me,
            onChange: (e: { target: { value: string } }) => onChange(e.target.value),
          },
          ...(data?.users ?? []).map((u) =>
            h(
              'option',
              { key: u.id, value: u.username },
              `${u.username}（${u.role === 'admin' ? t('owner') : t('subuser')}）`,
            ),
          ),
        )
      : null;

  const patchOk =
    patchState !== null &&
    patchState.settingsHostMode &&
    patchState.whitelist &&
    patchState.workspaceSearch &&
    patchState.connectionCookieBridge !== 'missing' &&
    patchState.connectionCookieBridge !== 'unsupported';
  const patchText =
    patchState === null ? t('patchUnknown') : patchOk ? t('patchOk') : t('patchBad');
  const managedUsers = overview?.users.filter((u) => u.role === 'user') ?? [];
  const updateDownloading = updateInfo?.phase === 'downloading';
  const updateInstalling = updateInfo?.phase === 'installing' || updateInfo?.phase === 'restarting';
  const updateProgressVisible = updateDownloading || updateInstalling || (updateInfo?.phase === 'ready' && updateInfo.pendingVersion !== null);
  const updateManualOnly = updateInfo?.env === 'docker' && !updateInfo.autoInstallSupported && updateInfo.manualCommand !== '';
  const updateProgress = updateInfo?.downloadPercent;
  const applyLabel = updateInfo?.phase === 'ready' && updateInfo.installConfirmationRequired
    ? t('updateApplyNow')
    : !updateInfo?.autoUpdateEnabled && updateInfo?.updateAvailable && updateInfo.pendingVersion === null
      ? t('updateDownloadPrepare')
      : t('updateApplyNow');

  const body = h(
    'div',
    { className: 'dshpw-body' },
    // ── 当前身份（原折叠头里的账号信息，独立分区后直接展示） ──
    h(
      'div',
      { className: 'dshpw-profile' },
      h('span', { className: 'dshpw-avatar', 'aria-hidden': 'true' }, (me || '?').slice(0, 1).toUpperCase()),
      h(
        'div',
        { className: 'dshpw-profile-copy' },
        h('span', { className: 'dshpw-profile-label' }, t('identity')),
        h('strong', null, me || '—'),
      ),
      isAdmin
        ? h('span', { className: 'dshpw-badge admin' }, t('owner'))
        : h('span', { className: 'dshpw-badge' }, t('subuser')),
      h(
        'button',
        {
          className: 'dshpw-btn danger dshpw-signout',
          disabled: signOutBusy || data === null,
          onClick: signOut,
          title: t('logoutHint'),
        },
        signOutBusy ? t('loggingOut') : t('logout'),
      ),
    ),
    // ── 聊天入口：按当前账号跨设备同步的显示偏好 ──
    h(
      'div',
      { className: 'dshpw-section dshpw-preference' },
      h('div', { className: 'dshpw-section-head' }, h('span', { className: 'dshpw-label' }, t('chatToggle'))),
      h(
        'label',
        { className: 'dshpw-switch' },
        h(
          'span',
          { className: 'dshpw-switch-copy' },
          h('strong', null, t('chatToggleDesc')),
          h('small', null, t('chatToggleHint')),
        ),
        h(
          'span',
          { className: 'dshpw-switch-control' },
          h('input', {
            type: 'checkbox',
            checked: chatEnabled,
            disabled: busy || data === null,
            onChange: toggleChatEntry,
            'aria-label': t('chatToggleDesc'),
          }),
          h('span', { className: 'dshpw-switch-track', 'aria-hidden': 'true' }, h('span', { className: 'dshpw-switch-thumb' })),
        ),
      ),
    ),
    // ── 远程设置：状态 + 重载 ──
    h(
      'div',
      { className: 'dshpw-section' },
      h(SectionHeader, { label: t('patch'), status: patchText, tone: patchOk ? 'success' : 'danger' }),
      h(
        'div',
        { className: 'dshpw-patch-actions dshpw-form-actions' },
        isAdmin &&
          h(
            'div',
            { className: 'dshpw-action-row' },
            h('span', { className: 'dshpw-action-copy dshpw-hint' }, t('patchHint2')),
            h('button', { className: 'dshpw-btn', disabled: busy, onClick: reloadPatch }, t('reloadPatch')),
          ),
      ),
    ),

    // ── 软件更新（自动/手动检查 + 空闲窗自动安装；状态所有用户可见，操作仅主用户） ──
    h(
      'div',
      { className: 'dshpw-section' },
      h(SectionHeader, {
        label: t('update'),
        status: updateChecking || updateInfo?.checking
          ? h('span', { className: 'dshpw-update-status', role: 'status', 'aria-live': 'polite' }, h('span', { className: 'dshpw-spinner', 'aria-hidden': 'true' }), t('updateChecking'))
          : updateInfo === null
            ? t('updateUnknown')
            : updateInfo.updateAvailable
              ? `${t('updateAvailable')} · ${updateInfo.latestVersion ?? '—'}`
              : `${t('updateUpToDate')} · ${updateInfo.currentVersion}`,
        tone: updateChecking || updateInfo?.checking ? 'neutral' : updateInfo?.updateAvailable ? 'warning' : updateInfo === null ? 'neutral' : 'success',
      }),

      updateInfo !== null
        ? h(
            'label',
            { className: 'dshpw-switch' },
            h(
              'span',
              { className: 'dshpw-switch-copy' },
              h('strong', null, t('updateAutoToggle')),
              h('small', null, updateInfo.autoUpdateEnabled ? t('updateEnabled') : t('updateDisabled')),
            ),
            h(
              'span',
              { className: 'dshpw-switch-control' },
              h('input', {
                type: 'checkbox',
                checked: updateInfo.autoUpdateEnabled,
                disabled: updateBusy || data === null || !isAdmin,
                onChange: toggleAutoUpdate,
                'aria-label': t('updateAutoToggle'),
              }),
              h('span', { className: 'dshpw-switch-track', 'aria-hidden': 'true' }, h('span', { className: 'dshpw-switch-thumb' })),
            ),
          )
        : null,
      updateInfo?.phase === 'ready' && updateInfo.installConfirmationRequired
        ? h('div', { className: 'dshpw-ok' }, t('updateDownloadReadyConfirm'))
        : null,
      updateInfo?.phase === 'ready' && !updateInfo.installConfirmationRequired && updateInfo.idleRemainingMs !== null
        ? h(
            'div',
            { className: 'dshpw-row' },
            h('span', null, t('updateReadyWaitIdle', { minutes: idleMinutes(updateInfo.idleRemainingMs) })),
          )
        : null,
      updateInfo?.lastError
        ? h('div', { className: 'dshpw-error' }, updateInfo.lastError)
        : null,
      updateManualOnly
        ? h(
            'div',
            { className: 'dshpw-update-manual-block' },
            h('div', { className: 'dshpw-hint' }, t('updateDockerManual')),
            h('div', { className: 'dshpw-hint dshpw-update-manual-command' }, updateInfo.manualCommand),
          )
        : null,
      h(
        'div',
        {
          className: `dshpw-action-row dshpw-update-actions${updateProgressVisible ? ' has-progress' : ' no-progress'}`,
        },
        isAdmin && updateProgressVisible &&
          h(
            'div',
            { className: 'dshpw-update-inline-progress', role: 'status', 'aria-live': 'polite' },
            h(
              'div',
              {
                className: `dshpw-progress-track${updateProgress === null ? ' indeterminate' : ''}`,
                role: 'progressbar',
                'aria-valuemin': 0,
                'aria-valuemax': 100,
                'aria-valuenow': updateProgress ?? undefined,
              },
              h('span', {
                className: 'dshpw-progress-fill',
                style: updateProgress === null ? undefined : { width: `${Math.max(0, Math.min(100, updateProgress ?? 0))}%` },
              }),
            ),
            h('span', { className: 'dshpw-hint' }, updateDownloading ? (updateInfo?.downloadMode === 'automatic' ? t('updateAutoDownloading') : t('updateManualDownloading')) : updateInstalling ? t('updateInstalling') : '100%'),
          ),
        isAdmin &&
          h(
            'button',
            { className: 'dshpw-btn', disabled: updateBusy || updateChecking || updateDownloading || updateInstalling, onClick: checkUpdate },
            updateChecking ? t('updateChecking') : t('updateCheck'),
          ),
        isAdmin &&
          h(
            'button',
            { className: 'dshpw-btn dshpw-update-apply', disabled: updateBusy || updateInfo === null || updateChecking || updateDownloading || updateInstalling || updateManualOnly, onClick: applyUpdate },
            applyLabel,
          ),
      ),
    ),

    // ── 修改密码 ──
    h(
      'div',
      { className: 'dshpw-section' },
      h(SectionHeader, { label: t('chgPw') }),
      isAdmin && h('span', { className: 'dshpw-hint' }, t('targetUser')),
      targetSelect(pwTarget, setPwTarget),
      // F-06：改自己需先验证当前密码（管理员改他人无需）
      (pwTarget === '' || pwTarget === me) &&
        h('input', {
          className: 'dshpw-input',
          type: 'password',
          // 使用标准 current-password 语义，让密码管理器能正确识别当前密码；
          // 侧栏搜索框的防自动填充由 dsh 补丁单独处理，不再牺牲这里的兼容性。
          autoComplete: 'current-password',
          name: 'current-password',
          placeholder: t('currentPwPh'),
          value: pwCurrent,
          onChange: (e: { target: { value: string } }) => setPwCurrent(e.target.value),
        }),
      h('input', {
        className: 'dshpw-input',
        type: 'password',
        autoComplete: 'new-password',
        name: 'new-password',
        placeholder: t('newPwPh'),
        value: pwNew,
        onChange: (e: { target: { value: string } }) => setPwNew(e.target.value),
      }),
      h('input', {
        className: 'dshpw-input',
        type: 'password',
        autoComplete: 'new-password',
        name: 'confirm-password',
        placeholder: t('confirmPwPh'),
        value: pwConfirm,
        onChange: (e: { target: { value: string } }) => setPwConfirm(e.target.value),
      }),
      h(
        'div',
        { className: 'dshpw-action-row dshpw-form-actions' },
        h('button', { className: 'dshpw-btn', disabled: busy, onClick: changePassword }, t('savePw')),
      ),
    ),

    // ── 修改用户名 ──
    h(
      'div',
      { className: 'dshpw-section' },
      h(SectionHeader, { label: t('chgName') }),
      isAdmin && h('span', { className: 'dshpw-hint' }, t('targetUser')),
      targetSelect(nameTarget, setNameTarget),
      h('input', {
        className: 'dshpw-input',
        autoComplete: 'off',
        name: 'dshpw-newname',
        placeholder: t('newNamePh'),
        value: nameNew,
        onChange: (e: { target: { value: string } }) => setNameNew(e.target.value),
      }),
      h(
        'div',
        { className: 'dshpw-action-row dshpw-form-actions' },
        h('button', { className: 'dshpw-btn', disabled: busy, onClick: rename }, t('saveName')),
      ),
      h('div', { className: 'dshpw-hint' }, t('nameHint')),
    ),

    // ── 子用户管理（仅主用户） ──
    isAdmin &&
      h(
        'div',
        { className: 'dshpw-section' },
        h(SectionHeader, { label: t('subusers') }),
        ...(data?.users ?? []).map((u) =>
          h(
            'div',
            { className: 'dshpw-user', key: u.id },
            h(
              'span',
              null,
              u.username,
              u.role === 'admin'
                ? h('span', { className: 'dshpw-badge admin' }, t('owner'))
                : h('span', { className: 'dshpw-badge' }, t('subuser')),
              u.last_login_at ? h('span', { className: 'dshpw-hint' }, t('lastLogin', { time: fmtTime(u.last_login_at) })) : null,
            ),
            u.username !== me &&
              h('button', { className: 'dshpw-btn danger', disabled: busy, onClick: () => removeUser(u.username) }, t('remove')),
          ),
        ),
        h('input', {
          className: 'dshpw-input',
          autoComplete: 'off',
          name: 'dshpw-subname',
          placeholder: t('subNamePh'),
          value: addName,
          onChange: (e: { target: { value: string } }) => setAddName(e.target.value),
        }),
        h('input', {
          className: 'dshpw-input',
          type: 'password',
          autoComplete: 'new-password',
          placeholder: t('subPwPh'),
          value: addPw,
          onChange: (e: { target: { value: string } }) => setAddPw(e.target.value),
        }),
        h(
          'div',
          { className: 'dshpw-action-row dshpw-form-actions' },
          h('button', { className: 'dshpw-btn', disabled: busy, onClick: addSubUser }, t('addSub')),
        ),
        h('div', { className: 'dshpw-hint' }, t('subHint')),
      ),


    // ── 子用户权限（仅主用户） ──
    isAdmin &&
      overview !== null &&
      h(
        'div',
        { className: 'dshpw-section' },
        h(SectionHeader, { label: t('perms'), status: managedUsers.length === 0 ? t('permsNoUsers') : undefined }),
        managedUsers.length === 0
          ? h('div', { className: 'dshpw-empty-state' }, h('strong', null, t('permsNoUsers')))
          : h(
              'div',
              { className: 'dshpw-perms-content' },
              h('div', { className: 'dshpw-hint' }, t('permsHint')),
              ...managedUsers.map((u) => {
            const d = permDrafts[u.id];
            if (!d) return null;
            return h(
              'div',
              { className: 'dshpw-perm', key: u.id },
              h(
                'div',
                { className: 'dshpw-perm-head' },
                h('strong', null, u.username),
                u.usage
                  ? h(
                      'span',
                      { className: 'dshpw-hint' },
                      `${t('usageTime')} ${Math.round(u.usage.activeSeconds / 60)}m · ${t('usageTokens')} ${u.usage.hourlyTokens}`,
                    )
                  : null,
                u.permissions.banned ? h('span', { className: 'dshpw-badge' }, t('banned')) : null,
              ),
              h('div', { className: 'dshpw-label' }, t('permsFolders')),
              workspaces.length === 0
                ? h('div', { className: 'dshpw-hint' }, t('permsNoWorkspaces'))
                : h(
                    'div',
                    { className: 'dshpw-workspaces' },
                    ...workspaces.map((workspace) => {
                      const enabled = enabledFolderSet(d).has(workspace.path);
                      return h(
                        'div',
                        { className: 'dshpw-workspace', key: workspace.path },
                        h(
                          'label',
                          { className: 'dshpw-switch dshpw-workspace-switch' },
                          h(
                            'span',
                            { className: 'dshpw-switch-copy' },
                            h('strong', null, workspace.title || workspace.path),
                            h('small', null, workspace.path),
                          ),
                          h(
                            'span',
                            { className: 'dshpw-switch-control' },
                            h('input', {
                              type: 'checkbox',
                              checked: enabled,
                              disabled: busy,
                              onChange: (e: { target: { checked: boolean } }) =>
                                toggleWorkspace(u.id, workspace, e.target.checked),
                              'aria-label': workspace.title || workspace.path,
                            }),
                            h('span', { className: 'dshpw-switch-track', 'aria-hidden': 'true' },
                              h('span', { className: 'dshpw-switch-thumb' }),
                            ),
                          ),
                        ),
                        enabled
                          ? h(
                              'div',
                              { className: 'dshpw-session-list' },
                              ...(workspace.sessions.length === 0
                                ? [h('span', { className: 'dshpw-hint' }, t('permsNoSessions'))]
                                : workspace.sessions.map((session) =>
                                    h(
                                      'label',
                                      { className: 'dshpw-session-check', key: session.id },
                                      h('input', {
                                        type: 'checkbox',
                                        checked: d.allowedSessionIds.includes(session.id),
                                        disabled: busy,
                                        onChange: (e: { target: { checked: boolean } }) =>
                                          toggleSession(u.id, session.id, e.target.checked),
                                      }),
                                      h('span', null, session.title || session.id),
                                    ),
                                  )),
                            )
                          : null,
                      );
                    }),
                  ),
              agentPresetStatus === 'unavailable'
                ? h(
                    'div',
                    { className: 'dshpw-row' },
                    h('div', { className: 'dshpw-label' }, t('permsAgentPresets')),
                    h('div', { className: 'dshpw-hint' }, t('permsAgentPresetsUnavailable')),
                  )
                : agentPresets.length > 0
                ? h(
                    'div',
                    { className: 'dshpw-row' },
                    h('div', { className: 'dshpw-label' }, t('permsAgentPresets')),
                    h(
                      'label',
                      { className: 'dshpw-check' },
                      h('input', {
                        type: 'checkbox',
                        checked: d.agentPresets === null,
                        disabled: busy,
                        onChange: (e: { target: { checked: boolean } }) =>
                          setDraft(u.id, { agentPresets: e.target.checked ? null : [] }),
                      }),
                      t('permsAgentPresetsUnrestricted'),
                    ),
                    ...(d.agentPresets === null
                      ? []
                      : agentPresets.map((preset) =>
                          h(
                            'label',
                            { className: 'dshpw-check', key: preset.id },
                            h('input', {
                              type: 'checkbox',
                              checked: (d.agentPresets ?? []).includes(preset.id),
                              disabled: busy || preset.broken !== undefined,
                              onChange: (e: { target: { checked: boolean } }) => {
                                const next = new Set(d.agentPresets ?? []);
                                if (e.target.checked) next.add(preset.id);
                                else next.delete(preset.id);
                                setDraft(u.id, { agentPresets: [...next] });
                              },
                            }),
                            h(
                              'span',
                              null,
                              preset.name || preset.id,
                              preset.broken !== undefined ? ` (${t('permsAgentPresetBroken')})` : '',
                            ),
                          ),
                        )),
                  )
                : null,
              overview.availableWebSocketPaths.length > 0
                ? h(
                    'div',
                    { className: 'dshpw-row' },
                    h('div', { className: 'dshpw-label' }, t('permsWebSockets')),
                    ...overview.availableWebSocketPaths.map((rule) =>
                      h(
                        'label',
                        { className: 'dshpw-check', key: rule },
                        h('input', {
                          type: 'checkbox',
                          checked: d.webSocketPaths.includes(rule),
                          disabled: busy,
                          onChange: (e: { target: { checked: boolean } }) => {
                            const next = new Set(d.webSocketPaths);
                            if (e.target.checked) next.add(rule);
                            else next.delete(rule);
                            setDraft(u.id, { webSocketPaths: [...next] });
                          },
                        }),
                        rule,
                      ),
                    ),
                  )
                : null,
              h(
                'select',
                {
                  className: 'dshpw-input',
                  value: d.sandbox,
                  'aria-label': t('permsSandbox'),
                  onChange: (e: { target: { value: string } }) => setDraft(u.id, { sandbox: e.target.value }),
                },
                h('option', { value: '' }, t('sandboxNone')),
                h('option', { value: 'read-only' }, t('sandboxReadOnly')),
                h('option', { value: 'workspace-write' }, t('sandboxWorkspace')),
                h('option', { value: 'danger-full-access' }, t('sandboxFull')),
              ),
              h(
                'div',
                { className: 'dshpw-row' },
                h('input', {
                  className: 'dshpw-input',
                  type: 'text',
                  inputMode: 'numeric',
                  pattern: '[0-9]*',
                  autoComplete: 'off',
                  name: 'dshpw-tokenlimit',
                  placeholder: t('permsToken'),
                  value: d.token,
                  onChange: (e: { target: { value: string } }) => setDraft(u.id, { token: e.target.value }),
                }),
                h('input', {
                  className: 'dshpw-input',
                  type: 'text',
                  inputMode: 'numeric',
                  pattern: '[0-9]*',
                  autoComplete: 'off',
                  name: 'dshpw-minlimit',
                  placeholder: t('permsMinutes'),
                  value: d.minutes,
                  onChange: (e: { target: { value: string } }) => setDraft(u.id, { minutes: e.target.value }),
                }),
              ),
              h(
                'div',
                { className: 'dshpw-row' },
                h(
                  'label',
                  { className: 'dshpw-check' },
                  h('input', {
                    type: 'checkbox',
                    checked: d.upload,
                    onChange: (e: { target: { checked: boolean } }) => setDraft(u.id, { upload: e.target.checked }),
                  }),
                  t('permsUpload'),
                ),
                h(
                  'label',
                  { className: 'dshpw-check' },
                  h('input', {
                    type: 'checkbox',
                    checked: d.git,
                    onChange: (e: { target: { checked: boolean } }) => setDraft(u.id, { git: e.target.checked }),
                  }),
                  t('permsGit'),
                ),
                h(
                  'label',
                  { className: 'dshpw-check' },
                  h('input', {
                    type: 'checkbox',
                    checked: d.ssh,
                    disabled: busy,
                    onChange: (e: { target: { checked: boolean } }) => setDraft(u.id, { ssh: e.target.checked }),
                  }),
                  t('permsSsh'),
                ),
                h(
                  'label',
                  { className: 'dshpw-check' },
                  h('input', {
                    type: 'checkbox',
                    checked: d.workspaceCreate,
                    onChange: (e: { target: { checked: boolean } }) => setDraft(u.id, { workspaceCreate: e.target.checked }),
                  }),
                  t('permsWorkspaceCreate'),
                ),
                h(
                  'label',
                  { className: 'dshpw-check' },
                  h('input', {
                    type: 'checkbox',
                    checked: d.banned,
                    onChange: (e: { target: { checked: boolean } }) => setDraft(u.id, { banned: e.target.checked }),
                  }),
                  t('permsBanned'),
                ),
              ),
              h(
                'div',
                { className: 'dshpw-action-row dshpw-form-actions' },
                h(
                  'button',
                  { className: 'dshpw-btn', disabled: busy, onClick: () => savePermissions(u.id) },
                  t('permsSave'),
                ),
              ),
            );
          }),
            ),
      ),


    error && h('div', { className: 'dshpw-error' }, error),
    notice && h('div', { className: 'dshpw-ok' }, notice),
  );

  return h('div', { className: 'dshpw-card' }, body);
}
