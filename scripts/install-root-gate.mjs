// 安装器首次安装特权门禁（纯逻辑，供 scripts/install.mjs 与回归测试共用）。
//
// 语义与 src/config.ts 的 autoTls 同源：只有「运行时不会绑定特权端口」的部署才允许非 root
// 首次安装——同时提供用户自管证书（MCP_GATEWAY_TLS_CERT + MCP_GATEWAY_TLS_KEY，两者 trim
// 后均非空），或 MCP_GATEWAY_AUTO_TLS 的取值在运行时判定为关闭。
//
// 关键对齐点（与 src/config.ts 的 autoTls 判定一致）：只有 1/true/yes/auto 视为显式开启；
// 空值（未设置）= 自动判断（未自备证书时启用，需要 root）；其余显式值——包括无法识别的
// 值——运行时一律按关闭处理（src/config.ts `autoTlsValueIsKnown` 为假 ⇒ autoTls=false），
// 因此同样属于非特权模式。单边或仅含空白的证书、单独设置 DSH_PASSWORDS_RUNTIME=docker
// 都不构成授权（仍需 root）。

export function isExplicitNonPrivilegedTlsMode(env = process.env) {
  const tlsCert = (env.MCP_GATEWAY_TLS_CERT ?? '').trim();
  const tlsKey = (env.MCP_GATEWAY_TLS_KEY ?? '').trim();
  if (tlsCert !== '' && tlsKey !== '') return true;
  const autoTlsRaw = (env.MCP_GATEWAY_AUTO_TLS ?? '').trim().toLowerCase();
  // 空值=自动判断（运行时启用自动 HTTPS），仍需 root。
  if (autoTlsRaw === '') return false;
  const autoOn = autoTlsRaw === '1' || autoTlsRaw === 'true' || autoTlsRaw === 'yes' || autoTlsRaw === 'auto';
  // 显式开启=特权；其余显式值（0/false/no 与无法识别的值）运行时都关闭自动 HTTPS。
  return !autoOn;
}

/**
 * 首次安装是否需要 root：Unix 且当前为非 root、且并非明确的非特权模式时为真。
 * uid 传 null/undefined（如 Windows 无 process.getuid）按「无法判定」处理，仅由 isWin 决定。
 */
export function firstInstallNeedsRoot({ isWin, uid, env = process.env }) {
  if (isWin) return false;
  if (uid === null || uid === undefined || uid === 0) return false;
  return !isExplicitNonPrivilegedTlsMode(env);
}

/**
 * 首次安装写入的 .env：端口/TLS/监听地址必须与安装时的模式一致，否则非 root 服务在运行时
 * 仍会因缺省 autoTls=true 去绑定 443/80、因缺省 host=0.0.0.0 把 HTTP 网关暴露到所有网卡。
 * 自动 HTTPS 保持原有 443/80 与隐式 0.0.0.0 默认；非特权模式持久化关闭开关或用户证书，
 * 端口默认 8080、监听地址默认 127.0.0.1（用户显式值优先）。
 */
export function firstInstallEnvContent(setupKey, dbEncKey, env = process.env) {
  const lines = [`SETUP_KEY=${setupKey}`, `MCP_DB_ENC_KEY=${dbEncKey}`];
  if (isExplicitNonPrivilegedTlsMode(env)) {
    const tlsCert = (env.MCP_GATEWAY_TLS_CERT ?? '').trim();
    const tlsKey = (env.MCP_GATEWAY_TLS_KEY ?? '').trim();
    if (tlsCert !== '' && tlsKey !== '') {
      lines.push(`MCP_GATEWAY_TLS_CERT=${tlsCert}`, `MCP_GATEWAY_TLS_KEY=${tlsKey}`);
    } else {
      lines.push('MCP_GATEWAY_AUTO_TLS=0');
    }
    // 非特权部署多为反代/本机访问：未显式指定监听地址时只绑回环，避免把明文 HTTP
    // 网关默认暴露到 0.0.0.0。用户显式给定的 host（如内网地址或 0.0.0.0）原样保留。
    const host = (env.MCP_GATEWAY_HOST ?? '').trim();
    lines.push(`MCP_GATEWAY_HOST=${host !== '' ? host : '127.0.0.1'}`);
    const port = (env.MCP_GATEWAY_PORT ?? '').trim();
    lines.push(`MCP_GATEWAY_PORT=${port !== '' ? port : '8080'}`);
    const redirect = (env.MCP_GATEWAY_REDIRECT_PORT ?? '').trim();
    if (redirect !== '') lines.push(`MCP_GATEWAY_REDIRECT_PORT=${redirect}`);
  } else {
    lines.push('MCP_GATEWAY_PORT=443', 'MCP_GATEWAY_REDIRECT_PORT=80');
  }
  return `${lines.join('\n')}\n`;
}
