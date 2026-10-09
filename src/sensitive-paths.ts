// 敏感路径判定（下载、目录删除、workspaceFiles//api/file 读取共用同一基列表）。
//
// 基列表：部署根（盖 .env/dist/scripts）、配置根、数据库及其 data/ 父两级（最上一级即
// 部署目录）、DSH 安装根、DSH 家目录（会话/设置/凭据）、本机 SSH 凭据、OS 系统目录。
// 调用方在通过会话/白名单/归属之后仍须独立拒绝这些路径：管理员可能把敏感目录的祖先
// 误登记为工作区，此时目标会同时命中白名单与归属，只有敏感基能挡住。
import { realpathSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { normalizePath } from './permissions.js';
import { findDshRoot } from './patch.js';

export interface SensitivePathCheckerConfig {
  /** 数据库文件路径：基列表含其自身、data/ 父级与再上一级部署目录。 */
  dbPath: string;
  /** dsh 安装根配置（config.patch.dshRoot）；留空时经 findDshRoot 自动探测。 */
  dshRoot: string;
  /** 部署根（gateway 产物所在仓库根）。 */
  gatewayRoot: string;
  /** 配置根（.env 所在目录）。 */
  configuredRoot: string;
}

export interface SensitivePathChecker {
  /** 候选路径是否命中敏感基（含相等与段边界子树包含）。 */
  isSensitivePath: (candidate: string) => boolean;
  /**
   * 敏感基列表（每次调用按当前文件系统状态重新求值：realpath 链接目标实时解析）。
   * 供目录删除的「在基内 / 包含基」反向判定复用，避免各处再复制一份基列表。
   */
  sensitivePathBases: () => string[];
}

export function createSensitivePathChecker(config: SensitivePathCheckerConfig): SensitivePathChecker {
  // findDshRoot 未显式配置 dshRoot 时会 spawn `npm root -g`，而文件读取是高频路径，
  // 不能每请求起子进程，因此按需探测一次并缓存结果：探测结果只取决于显式配置与 npm
  // 全局根，与目录链接无关，固化是安全的。
  let dshRootResolved = false;
  let dshRoot: string | null = null;
  const resolvedDshRoot = (): string | null => {
    if (!dshRootResolved) {
      dshRoot = findDshRoot(config.dshRoot);
      dshRootResolved = true;
    }
    return dshRoot;
  };

  const lexicalPath = (value: string): string => path.resolve(value);
  const realpathBestEffort = (value: string): string => {
    try {
      return realpathSync(value);
    } catch {
      return lexicalPath(value);
    }
  };
  const pathAncestors = (value: string): string[] => [
    value,
    path.dirname(value),
    path.dirname(path.dirname(value)),
  ];

  // 每次校验重算 realpath 基：部署根/配置根/DSH 家目录/SSH 目录的软链（如 ~/.ssh 指向
  // 外部凭据目录）可能在首次调用之后才建立或改指，若像旧实现那样永久缓存 realpath 结果，
  // 调用方传入的 canonical 候选就会对照不到任何基而静默漏放（R7）。词法基与 realpath 基
  // 都必须登记：调用方应同时用词法路径与 canonical 路径各判一次（见调用点注释）。
  const sensitivePathBases = (): string[] => {
    const dbLexical = lexicalPath(config.dbPath);
    const dbReal = realpathBestEffort(config.dbPath);
    const home = os.homedir();
    const dshHome = process.env.DSH_HOME !== undefined && process.env.DSH_HOME !== ''
      ? lexicalPath(process.env.DSH_HOME)
      : path.join(home, '.dsh');
    const dshRootPath = resolvedDshRoot();
    const sshDir = path.join(home, '.ssh');
    return [
      lexicalPath(config.gatewayRoot),
      realpathBestEffort(config.gatewayRoot),
      lexicalPath(config.configuredRoot),
      realpathBestEffort(config.configuredRoot),
      ...pathAncestors(dbLexical),
      ...pathAncestors(dbReal),
      dshRootPath !== null ? lexicalPath(dshRootPath) : '',
      dshRootPath !== null ? realpathBestEffort(dshRootPath) : '',
      dshHome,
      realpathBestEffort(dshHome),
      // SSH 凭据：词法 ~/.ssh 与其当次 realpath 链接目标都入基。调用方传的是 canonical
      // 路径，若 ~/.ssh 被软链到别处，仅登记词法基会静默漏放真实凭据目录（R7）。
      sshDir,
      realpathBestEffort(sshDir),
      ...(process.platform === 'win32' ? [] : ['/etc', '/proc', '/sys', '/dev', '/boot']),
    ].filter((p) => p !== '');
  };

  // 候选（canonicalizePathBestEffort 产物为正斜杠形态）与基（path.resolve/join/realpath
  // 产物在 Windows 为反斜杠）统一走 normalizePath 后比较；否则 Windows 上前缀判定会因
  // 分隔符不一致而漏放。
  //
  // Windows 文件系统大小写不敏感：normalizePath 只统一盘符大小写，其余段保留原样，
  // 而基来自配置/环境（gatewayRoot、DSH_HOME、os.homedir()），候选多经 realpath 归到
  // 磁盘大小写。两者大小写不一致（如 C:/Users/Sky 与 C:/Users/sky）时前缀比较会漏放，
  // 敏感基静默失效。因此 win32 下比较前统一折叠大小写；POSIX 保持大小写敏感。
  const caseFold = process.platform === 'win32'
    ? (value: string): string => value.toLowerCase()
    : (value: string): string => value;
  const isSensitivePath = (candidate: string): boolean => {
    const normalized = caseFold(normalizePath(candidate));
    return sensitivePathBases().some((base) => {
      const normalizedBase = caseFold(normalizePath(base));
      return normalized === normalizedBase || normalized.startsWith(`${normalizedBase}/`);
    });
  };

  return { isSensitivePath, sensitivePathBases };
}
