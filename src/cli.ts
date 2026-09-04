#!/usr/bin/env node
// 入口：serve-gateway（登录网关，唯一模式；serve 为其别名）
//
// 端口/主机/上游三层配置（优先级从高到低）：
//   1. 启动参数:  node dist/cli.js serve-gateway --port 9000 --host 0.0.0.0
//   2. 环境变量:  MCP_GATEWAY_PORT=9000 node dist/cli.js serve-gateway
//   3. .env 文件: MCP_GATEWAY_PORT=9000
// 云服务器上 HTTP 端口未必开放 8080，部署时用以上任一方式指定实际端口。
//
// 远程设置补丁：强制启用，网关启动时自动应用（幂等）——
// dsh 升级覆盖文件后，重启网关就会自动重打，无需手动操作。
// 也可手动：node dist/cli.js patch [status]
import { loadConfig } from './config.js';
import { Database } from './db.js';
import { AuthService } from './auth.js';
import { createGatewayServer, createRedirectServer } from './gateway.js';
import { createFieldCrypto } from './encrypt.js';
import { ensureCertificate, certExpiryMs, certMatchesDomain, detectPublicIp, readCertMeta } from './acme.js';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  findDshRoot,
  applyRemotePatch,
  rollbackPatch,
  restartDshWeb,
  patchStatus,
} from './patch.js';
import { t, resolveCliLang } from './i18n.js';
import { UpdateEngine } from './update.js';

/** CLI 输出语言：LANG / LC_ALL / LC_MESSAGES 以 en 开头则英文，否则中文 */
const lang = resolveCliLang();
const tr = (key: string, params?: Record<string, string | number>) => t(lang, key, params);

interface CliOverrides {
  port?: number;
  host?: string;
  upstream?: string;
}

/** 解析 --port/--host/--upstream 参数（支持 --k=v 与 --k v 两种写法） */
function parseCliOverrides(argv: string[]): CliOverrides {
  const out: CliOverrides = {};
  const take = (index: number, name: string): string | null => {
    const next = argv[index + 1];
    if (next === undefined || next.startsWith('--')) {
      console.error(`[dsh-passwords] ${tr('cli.warnMissingValue', { name })}`);
      return null;
    }
    return next;
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--port' || arg === '--host' || arg === '--upstream') {
      const value = take(i, arg);
      if (value === null) continue;
      if (arg === '--port') {
        const port = Number(value);
        // 0/负数/非整数都拒绝（0 会触发随机端口，与 config.ts 的 >0 校验不一致）
        if (!Number.isInteger(port) || port <= 0 || port > 65535) {
          console.error(`[dsh-passwords] ${tr('cli.warnInvalidPort', { value })}`);
        } else {
          out.port = port;
        }
      } else if (arg === '--host') {
        out.host = value;
      } else {
        out.upstream = value;
      }
      i++;
    } else if (arg.startsWith('--port=')) {
      const port = Number(arg.slice('--port='.length));
      if (Number.isInteger(port) && port > 0 && port <= 65535) out.port = port;
    } else if (arg.startsWith('--host=')) {
      out.host = arg.slice('--host='.length);
    } else if (arg.startsWith('--upstream=')) {
      out.upstream = arg.slice('--upstream='.length);
    }
  }
  return out;
}

/** 审计日志查看命令：node dist/cli.js audit [--limit N]（自动解密敏感字段） */
function runAudit(argv: string[]): void {
  const limitArg = argv.indexOf('--limit');
  let limit = 30;
  if (limitArg >= 0 && argv[limitArg + 1] !== undefined) {
    const parsed = Number(argv[limitArg + 1]);
    // 只接受 1-1000 的整数（负数/浮点/科学计数法/1e2 都会产生非预期分页）
    if (Number.isInteger(parsed) && parsed > 0 && parsed <= 1000) {
      limit = parsed;
    } else {
      console.error(`[dsh-passwords] ${tr('cli.warnInvalidLimit', { value: argv[limitArg + 1] })}`);
    }
  }
  const config = loadConfig();
  const db = new Database(config.dbPath, createFieldCrypto(config.dbEncKey, config.setupKey));
  db.init();
  const rows = db.listAuditLogs(limit);
  if (rows.length === 0) {
    console.log(tr('cli.noAudit'));
    return;
  }
  for (const row of rows) {
    console.log(
      `[${row.created_at}] ${row.event_type}  username=${row.username ?? '-'}  ip=${row.ip ?? '-'}`,
    );
    if (row.user_agent) console.log(`    ua: ${row.user_agent}`);
    if (row.detail) console.log(`    detail: ${row.detail}`);
  }
}

/** 服务名白名单：systemctl restart <service> 拼到 shell 命令里，必须校验字符集 */
const SERVICE_NAME_RE = /^[A-Za-z0-9_.@-]+$/;
const EXIT_DSH_ROOT_UNAVAILABLE = 34;
const EXIT_ALPHA3_SETTINGS_UNAVAILABLE = 35;
const EXIT_PATCH_VERIFICATION_FAILED = 36;
const DSH_REMOTE_COOKIE_BRIDGE_RE =
  /^0\.1\.2-(?:alpha\.(?:[3-9]|[1-9][0-9]+)|rc\.(?:[1-9][0-9]*))$/;

function requiresCookieBridge(dshRoot: string): boolean {
  try {
    const packageJson = JSON.parse(readFileSync(path.join(dshRoot, 'package.json'), 'utf8')) as { version?: unknown };
    // alpha.3 and the 0.1.2 rc releases changed the client module/connection
    // contract. Their public Host API still has no cookie export, so a missing
    // private bridge must fail closed. Keep this range bounded to the known
    // 0.1.2 layouts instead of forcing an unverified future DSH through it.
    return typeof packageJson.version === 'string' && DSH_REMOTE_COOKIE_BRIDGE_RE.test(packageJson.version);
  } catch {
    return false;
  }
}

/** 补丁管理命令：node dist/cli.js patch [status]（补丁强制启用；无参数=立即重载） */
function runPatch(argv: string[]): void {
  const action = argv[0];
  const config = loadConfig();
  const root = findDshRoot(config.patch.dshRoot);
  if (!root) {
    console.error(`[dsh-passwords] ${tr('cli.noDshRoot')}`);
    // Stable machine-readable code: uninstall must not parse localized stderr.
    process.exit(EXIT_DSH_ROOT_UNAVAILABLE);
  }
  // 服务名注入防护：与 patch.ts 的 restartDshWeb 同口径，CLI 路径也校验
  if (config.patch.restartService && !SERVICE_NAME_RE.test(config.patch.restartService)) {
    console.error(`[dsh-passwords] ${tr('cli.warnInvalidService', { service: config.patch.restartService })}`);
    process.exit(1);
  }
  if (action === 'status') {
    const status = patchStatus(root);
    // Docker 初始化需要据此 fail-closed：文本输出面向人，JSON 输出面向脚本，
    // 避免解析本地化文案后误把未打补丁的容器带到线上。
    if (argv.includes('--json')) {
      console.log(JSON.stringify({ dshRoot: root, ...status }));
      return;
    }
    console.log(`${tr('cli.dshDir')}: ${root}`);
    console.log(
      `  ${tr('cli.hostMode')}: ${status.settingsHostMode ? tr('cli.patched') : tr('cli.notPatched')}`,
    );
    console.log(
      `  ${tr('cli.whitelist')}: ${status.whitelist ? tr('cli.patched') : tr('cli.notPatched')}`,
    );
    console.log(
      `  ${tr('cli.workspaceSearch')}: ${status.workspaceSearch ? tr('cli.patched') : tr('cli.notPatched')}`,
    );
    console.log(
      `  ${tr('cli.bindAll')}: ${status.bindAll ? tr('cli.patched') : tr('cli.notPatched')}`,
    );
    console.log(`  connection cookie bridge: ${status.connectionCookieBridge}`);
    return;
  }
  console.log(`${tr('cli.dshDir')}: ${root}`);
  if (action === undefined || action === 'on' || action === 'reload') {
    const result = applyRemotePatch(root);
    console.log(`  ${tr('cli.result')}: ${result}`);
    if (result === 'applied' && config.patch.restartService) {
      console.log(`  ${tr('cli.restarting', { service: config.patch.restartService })}`);
      // CLI 进程跑完就退出，不能用延迟定时器（unref 定时器会被丢弃）；直接同步重启
      try {
        const restarted = spawnSync('systemctl', ['restart', config.patch.restartService], { stdio: 'inherit' });
        if (restarted.status !== 0) {
          console.error(`  ${tr('cli.restartFailed')}${restarted.error ? `: ${String(restarted.error)}` : ''}`);
        }
      } catch (error) {
        console.error(`  ${tr('cli.restartFailed')}: ${String(error)}`);
      }
    }
    return;
  }
  if (action === 'off') {
    // 回滚补丁：从 .bak-dshpw 恢复原始文件（补丁导致设置页异常时用）
    const result = rollbackPatch(root);
    console.log(`  ${tr('cli.result')}: ${result}`);
    if (result === 'modified') {
      console.error('[dsh-passwords] patch rollback refused: a patched DSH bundle was modified by another tool');
      process.exit(1);
    }
    if (result === 'rolled-back' && config.patch.restartService && !argv.includes('--no-restart')) {
      console.log(`  ${tr('cli.restarting', { service: config.patch.restartService })}`);
      try {
        const restarted = spawnSync('systemctl', ['restart', config.patch.restartService], { stdio: 'inherit' });
        if (restarted.status !== 0) {
          console.error(`  ${tr('cli.restartFailed')}${restarted.error ? `: ${String(restarted.error)}` : ''}`);
        }
      } catch (error) {
        console.error(`  ${tr('cli.restartFailed')}: ${String(error)}`);
      }
    }
    return;
  }
  console.error(tr('cli.usage'));
  process.exit(1);
}

async function boot() {
  const config = loadConfig();
  if (!config.setupKey || config.setupKey === 'change-me-to-a-strong-random-key') {
    console.error(`[dsh-passwords] ${tr('cli.needSetupKey')}`);
    process.exit(1);
  }

  const cli = parseCliOverrides(process.argv.slice(3));

  // 启动参数覆盖 .env / 环境变量
  if (cli.port !== undefined) config.gateway.port = cli.port;
  if (cli.host !== undefined) config.gateway.host = cli.host;
  if (cli.upstream !== undefined) config.gateway.upstream = cli.upstream;

  // ── 自动 HTTPS：域名补全（零配置探测公网 IP → <IP>.sslip.io）+ 端口默认 ──
  // 失败即拒绝启动（fail-closed）：密码门绝不静默降级为明文 HTTP。
  // 需要 HTTP 的用户必须显式关闭（MCP_GATEWAY_AUTO_TLS=0）或走 scripts/start-http.mjs。
  const portExplicit = cli.port !== undefined || process.env.MCP_GATEWAY_PORT !== undefined;
  if (config.gateway.autoTls) {
    if (config.gateway.domain === '') {
      const ip = await detectPublicIp();
      if (ip !== null) {
        config.gateway.domain = `${ip}.sslip.io`;
      } else {
        console.error(`[dsh-passwords] ${tr('cli.exitNoDomain', { code: 31 })}`);
        console.error(`[dsh-passwords] ${tr('cli.exitNoDomainHint')}`);
        process.exit(31);
      }
    }
    if (!portExplicit) config.gateway.port = 443;
  }

  if (config.gateway.autoTls && config.gateway.port === config.gateway.redirectPort) {
    console.error(`[dsh-passwords] ${tr('cli.exitPortBusy', { code: 32, error: 'HTTPS 端口不能与 HTTP/ACME 重定向端口相同' })}`);
    process.exit(32);
  }

  // ── 远程设置补丁：强制启用，网关每次启动自动应用（幂等） ──
  // The public gateway has no useful or safe degraded mode without its DSH
  // contract. Root discovery, patching, and post-patch verification must all
  // finish before any database, redirect, TLS, or public listener is created.
  const root = findDshRoot(config.patch.dshRoot);
  if (!root) {
    console.error(`[dsh-passwords] ${config.patch.dshRoot ? tr('cli.dshRootMissing') : tr('cli.noDshRoot')}`);
    process.exit(EXIT_DSH_ROOT_UNAVAILABLE);
  }
  try {
    const result = applyRemotePatch(root);
    if (result === 'missing') {
      console.error(`[dsh-passwords] ${tr('cli.patchTargetMissing')}`);
      process.exit(EXIT_ALPHA3_SETTINGS_UNAVAILABLE);
    }
    if (result === 'applied') {
      console.error(`[dsh-passwords] ${tr('cli.patchApplied')}`);
      if (config.patch.restartService) restartDshWeb(config.patch.restartService, 800);
    }
    const status = patchStatus(root);
    if (requiresCookieBridge(root)) {
      if (!status.settingsHostMode) {
        console.error('[dsh-passwords] DSH 0.1.2 alpha/rc settings patch is missing or unsupported; refusing to start the public gateway');
        process.exit(EXIT_ALPHA3_SETTINGS_UNAVAILABLE);
      }
      if (status.connectionCookieBridge !== 'patched' && status.connectionCookieBridge !== 'native') {
        console.error('[dsh-passwords] DSH 0.1.2 alpha/rc requires an authenticated Cookie bridge; refusing to start the public gateway');
        process.exit(33);
      }
    }
  } catch (error) {
    console.error(`[dsh-passwords] ${tr('cli.patchSyncFailed')}:`, error);
    process.exit(EXIT_PATCH_VERIFICATION_FAILED);
  }

  const db = new Database(config.dbPath, createFieldCrypto(config.dbEncKey, config.setupKey));
  db.init();

  const auth = new AuthService(config, db);

  // ── 80 端口：301 跳转 + ACME HTTP-01 挑战应答 ──
  // 自动 HTTPS 需要先监听 80（Let's Encrypt 从 80 校验挑战），再签发证书
  const challengeStore = config.gateway.autoTls ? new Map<string, string>() : undefined;
  const redirect = createRedirectServer(config, challengeStore);
  if (redirect !== null) {
    redirect.on('error', (error) => {
      console.error(`[dsh-passwords] ${tr('cli.redirect')}: ${String(error)}`);
    });
    redirect.listen(config.gateway.redirectPort!, config.gateway.host, () => {
      console.error(
        `[dsh-passwords] ${tr('cli.redirect')}: http://${config.gateway.host}:${config.gateway.redirectPort} → 301 https://…`,
      );
    });
  }

  // ── 自动 HTTPS：申请/续期证书（签发失败 → 拒绝启动，错误码 30） ──
  if (config.gateway.autoTls && config.gateway.tls !== null && challengeStore !== undefined) {
    const acmeDir = path.dirname(config.gateway.tls.cert);
    console.error(`[dsh-passwords] ${tr('cli.acmeIssuing', { domain: config.gateway.domain })}`);
    try {
      const result = await ensureCertificate({
        domain: config.gateway.domain,
        email: config.gateway.acmeEmail || undefined,
        staging: config.gateway.acmeStaging,
        acmeDir,
        challengeStore,
      });
      console.error(
        `[dsh-passwords] ${tr('cli.acmeIssued', { domain: config.gateway.domain, date: new Date(result.expiresAt).toISOString() })}`,
      );
    } catch (error) {
      const oldExpiry = certExpiryMs(config.gateway.tls.cert);
      // 旧证书回退前必须确认它仍匹配当前域名/签发环境：换 MCP_GATEWAY_DOMAIN
      // 或切换 staging 后新证书签发失败时，旧证书已过期语义——继续用它会给新域名
      // 提供旧域名的证书（浏览器域名不匹配）。旧版本无 meta.json 时退回 SAN/CN 判定。
      const meta = readCertMeta(path.join(acmeDir, 'meta.json'));
      const certDomainOk =
        meta !== null
          ? meta.domain === config.gateway.domain && meta.staging === config.gateway.acmeStaging
          : certMatchesDomain(config.gateway.tls.cert, config.gateway.domain);
      if (oldExpiry !== null && oldExpiry > Date.now() && certDomainOk) {
        // 现有证书仍在有效期内且匹配当前域名（例如续期因网络抖动失败）：继续用它，后台定时重试续期
        console.error(`[dsh-passwords] ${tr('cli.acmeFallbackOld')}: ${String(error)}`);
      } else {
        // 没有可用证书 → 拒绝启动，绝不静默降级为明文 HTTP
        console.error(
          `[dsh-passwords] ${tr('cli.exitCertFailed', { code: 30, error: String(error) })}`,
        );
        console.error(`[dsh-passwords] ${tr('cli.exitCertHint')}`);
        process.exit(30);
      }
    }
    // 续期调度：每天检查一次，到期前 30 天自动续期。
    // TLS 每次握手动态读证书文件（SNICallback），续期写入后无需重启即生效。
    if (config.gateway.tls !== null) {
      setInterval(() => {
        const expiry = certExpiryMs(config.gateway.tls!.cert);
        if (expiry !== null && expiry - Date.now() > 30 * 24 * 3600 * 1000) return;
        void (async () => {
          try {
            const result = await ensureCertificate({
              domain: config.gateway.domain,
              email: config.gateway.acmeEmail || undefined,
              staging: config.gateway.acmeStaging,
              acmeDir,
              challengeStore,
            });
            console.error(
              `[dsh-passwords] ${tr('cli.acmeIssued', { domain: config.gateway.domain, date: new Date(result.expiresAt).toISOString() })}`,
            );
          } catch (error) {
            console.error(`[dsh-passwords] ${tr('cli.acmeRenewFailed')}: ${String(error)}`);
          }
        })();
      }, 24 * 3600 * 1000);
    }
  }

  const tlsOn = config.gateway.tls !== null;
  // 自动更新引擎（空闲窗安装 + 限速下载）；由网关中间件刷新活动时间
  const updateEngine = new UpdateEngine(config, db);
  const gateway = createGatewayServer(config, auth, db, updateEngine);

  // 端口被占用等监听失败：给出错误码退出（不崩溃在未处理的 error 事件上）
  gateway.on('error', (error) => {
    console.error(`[dsh-passwords] ${tr('cli.exitPortBusy', { code: 32, error: String(error) })}`);
    process.exit(32);
  });

  gateway.listen(config.gateway.port, config.gateway.host, () => {
    console.error(
      `[dsh-passwords] ${tr('cli.gatewayListening', { mode: tlsOn ? 'HTTPS' : 'HTTP' })}: ${tlsOn ? 'https' : 'http'}://${config.gateway.host}:${config.gateway.port} → ${tr('cli.upstream')} ${config.gateway.upstream}`,
    );
    console.error(`[dsh-passwords] ${tr('cli.db')}: ${config.dbPath}`);
    if (!tlsOn) {
      // 显式关闭自动 HTTPS 才走得到这里：给出醒目危险提示
      console.error(`[dsh-passwords] ${tr('cli.httpWarning')}`);
    }
    if (tlsOn && config.gateway.autoTls && config.gateway.domain !== '') {
      console.error(
        `[dsh-passwords] ${tr('cli.publicUrl')}: https://${config.gateway.domain}${config.gateway.port === 443 ? '' : `:${config.gateway.port}`}`,
      );
    }
    // 网关就绪后启动更新引擎：启动即查一次 + 每 24h 重检 + 空闲窗自动安装
    updateEngine.start();
  });

  // ── 父进程看门狗：由 dsh 插件拉起时（DSH_GATEWAY_PARENT_PID），
  // 宿主 dsh 退出后密码门随之停止，避免残留进程占用端口 ──
  const parentPid = Number(process.env.DSH_GATEWAY_PARENT_PID ?? '');
  if (Number.isInteger(parentPid) && parentPid > 0) {
    console.error(`[dsh-passwords] ${tr('cli.watchParent', { pid: parentPid })}`);
    // 记录父进程启动时刻（/proc/<pid>/stat field 22，jiffies）：kill(pid,0) 只
    // 验证 PID 存在，父进程死后 PID 被系统复用时看门狗会永不退出（僵尸进程）。
    // 读不到 /proc（非 Linux）时退化为仅 PID 存活判断。
    const readParentStart = (): number | null => {
      try {
        const stat = readFileSync(`/proc/${parentPid}/stat`, 'utf8');
        const afterComm = stat.slice(stat.lastIndexOf(')') + 2);
        const starttime = Number(afterComm.split(' ')[19]);
        return Number.isFinite(starttime) ? starttime : null;
      } catch {
        return null;
      }
    };
    const parentStart = readParentStart();
    const watchdog = setInterval(() => {
      try {
        process.kill(parentPid, 0);
      } catch {
        console.error(`[dsh-passwords] ${tr('cli.parentGone')}`);
        process.exit(0);
        return;
      }
      // PID 仍在但启动时刻变了 → 原父进程已死，PID 被复用 → 退出
      if (parentStart !== null) {
        const now = readParentStart();
        if (now !== null && now !== parentStart) {
          console.error(`[dsh-passwords] ${tr('cli.parentGone')}`);
          process.exit(0);
        }
      }
    }, 3000);
    watchdog.unref();
  }

  process.on('SIGINT', () => {
    updateEngine.dispose();
    gateway.close();
    redirect?.close();
    process.exit(0);
  });
  process.on('SIGTERM', () => {
    updateEngine.dispose();
    gateway.close();
    redirect?.close();
    process.exit(0);
  });
}

/** 包根目录（dist/cli.js → 项目根） */
const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** 一键安装：npm 包场景复用 scripts/install.mjs（预构建检测自动跳过依赖/编译） */
function runInstall(): void {
  const script = path.join(PACKAGE_ROOT, 'scripts', 'install.mjs');
  if (!existsSync(script)) {
    console.error(`[dsh-passwords] ${tr('cli.installScriptMissing', { path: script })}`);
    process.exit(1);
  }
  const result = spawnSync(process.execPath, [script], {
    cwd: PACKAGE_ROOT,
    stdio: 'inherit',
  });
  process.exit(result.status ?? 1);
}

/** 从 profile 安全注销本插件；保留部署目录、配置、数据库和证书。 */
function runUninstall(): void {
  const script = path.join(PACKAGE_ROOT, 'scripts', 'uninstall.mjs');
  if (!existsSync(script)) {
    console.error(`[dsh-passwords] uninstall script missing: ${script}`);
    process.exit(1);
  }
  const result = spawnSync(process.execPath, [script], {
    cwd: PACKAGE_ROOT,
    stdio: 'inherit',
  });
  process.exit(result.status ?? 1);
}

/** Docker 专用初始化：状态卷、profile、反代 HTTP 配置与补丁校验。 */
function runDockerInit(): void {
  const script = path.join(PACKAGE_ROOT, 'scripts', 'docker-init.mjs');
  if (!existsSync(script)) {
    console.error(`[dsh-passwords] ${tr('cli.dockerInitScriptMissing', { path: script })}`);
    process.exit(1);
  }
  const result = spawnSync(process.execPath, [script], {
    cwd: PACKAGE_ROOT,
    stdio: 'inherit',
  });
  process.exit(result.status ?? 1);
}

// CLI 分发：install | uninstall | docker-init | audit | patch | serve-gateway（--version/-v 打印版本）
if (process.argv[2] === '--version' || process.argv[2] === '-v' || process.argv[2] === 'version') {
  try {
    const pkg = JSON.parse(readFileSync(path.join(PACKAGE_ROOT, 'package.json'), 'utf8')) as {
      version?: string;
    };
    console.log(pkg.version ?? 'unknown');
  } catch {
    console.log('unknown');
  }
} else if (process.argv[2] === 'install') {
  runInstall();
} else if (process.argv[2] === 'uninstall') {
  runUninstall();
} else if (process.argv[2] === 'docker-init') {
  runDockerInit();
} else if (process.argv[2] === 'audit') {
  runAudit(process.argv.slice(3));
} else if (process.argv[2] === 'patch') {
  runPatch(process.argv.slice(3));
} else if (process.argv[2] === undefined || process.argv[2] === 'serve-gateway' || process.argv[2] === 'serve') {
  boot().catch((error) => {
    console.error(`[dsh-passwords] ${tr('cli.startFailed')}:`, error);
    process.exit(1);
  });
} else {
  // 未知子命令：报 usage 而不是静默启动网关（拼错命令不会误开服务）
  console.error(`[dsh-passwords] ${tr('cli.usage')}`);
  process.exit(1);
}
