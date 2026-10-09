// 聊天媒体（sticker / image / video）内聚功能簇：类型、策略常量、私有目录、
// helpers、init/PUT/serve 路由，以及周期性回收（sweep）。
//
// 三步上传协议（见 docs/plans/2026-09-15-model-restrictions-chat-media-design.md）：
//   1. POST /gateway/api/message-media/init  签发不透明 uploadId（DB 行置 pending）
//   2. PUT  /gateway/api/message-media/:id   流式接收二进制 → 魔数校验 → 原子转正
//   3. POST /gateway/api/messages            带 mediaIds 绑定到消息（同事务）
// 文件本体写在 data/message-media/ 私有目录，文件名恒为随机 storage key，
// 绝不使用用户提供的路径/文件名（原始名只进 DB 作展示元数据）。
//
// 权限：主用户不受 allow_chat_media 限制；子用户默认关闭（effectivePermissions
// 的缺省行已给 false），且每个上传/下载都要重新判定，不缓存授权结果。
//
// 本模块不 import gateway.ts：外部依赖（db / dbPath / effectivePermissions /
// apiAuth / jsonBody）经 MediaRoutesDeps 注入，注册后交回网关：sweepRate(now) 与
// sweepMedia(now) 分别接回原 mediaInitRate 与 DB 回收两处位置（保持原相对时序），
// chatMediaAllowed 供留言模块复用同一授权口径。
import {
  createReadStream,
  createWriteStream,
  closeSync,
  constants as fsConstants,
  fstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  realpathSync,
  renameSync,
  statSync,
  unlinkSync,
  type ReadStream,
} from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import path from 'node:path';
import type { Express, Request, RequestHandler, Response } from 'express';
import { MediaError, type Database, type UserPermissionsRow } from './db.js';
import { isDangerousUploadName } from './permissions.js';

/** apiAuth 解析出的当前用户（与 gateway 的 authedUser 结构一致） */
export interface MediaAuthedUser {
  userId: number;
  username: string;
  role: 'admin' | 'user';
}

/** 网关媒体路由需要注入的依赖面（由 createGatewayServer 提供） */
export interface MediaRoutesDeps {
  db: Database;
  /** SQLite 文件路径：媒体私有目录与它同锚（dbPath 的 data/ 下） */
  dbPath: string;
  effectivePermissions: (userId: number) => UserPermissionsRow;
  apiAuth: (req: Request, res: Response, requireAdmin?: boolean) => MediaAuthedUser | null;
  jsonBody: RequestHandler;
}

/** 注册结果：把媒体专用的周期清理与授权判定接回网关 */
export interface MediaRoutesHandle {
  /**
   * 子用户聊天媒体权限判定（主用户不受限）。留言模块复用同一授权口径，
   * 由网关在注册留言路由时注入，避免两处实现漂移。
   */
  chatMediaAllowed(role: 'admin' | 'user', userId: number): boolean;
  /**
   * 周期清理之一（网关每 10 分钟调用一次）：裁剪 init 限流滑动窗口。
   * 独立暴露是为了让网关在【原 mediaInitRate 循环的位置】原位调用，
   * 与 DB 回收（sweepMedia）之间保持迁移前被 cap / pruneStaleSecurityRows
   * 分隔的相对时序。
   */
  sweepRate(now: number): void;
  /**
   * 周期清理之二：回收过期/未完成上传的媒体元数据与文件本体（含 DB 回收），
   * 对应迁移前位于 cap 段之后的回收 try 块。
   */
  sweepMedia(now: number): void;
}

/**
 * 注册全部聊天媒体路由，并返回周期清理句柄。
 * 注册顺序与迁移前一致：init → PUT → GET/HEAD serve。
 */
export function registerMediaRoutes(app: Express, deps: MediaRoutesDeps): MediaRoutesHandle {
  const { db, dbPath, effectivePermissions, apiAuth, jsonBody } = deps;

  type ChatMediaKind = 'sticker' | 'image' | 'video';

  /** 每种类型的允许 MIME → 允许的魔数族（按字节前缀判定，不看声明头） */
  const MEDIA_POLICY: Record<ChatMediaKind, { maxBytes: number; mimes: readonly string[] }> = {
    // sticker 通常是透明小图：PNG/JPEG/WebP/GIF 都允许（设计稿「必要时 GIF」）
    sticker: { maxBytes: 2 * 1024 * 1024, mimes: ['image/png', 'image/jpeg', 'image/webp', 'image/gif'] },
    image: {
      maxBytes: 10 * 1024 * 1024,
      mimes: ['image/png', 'image/jpeg', 'image/webp', 'image/gif'],
    },
    video: { maxBytes: 100 * 1024 * 1024, mimes: ['video/mp4', 'video/webm'] },
  };

  /** 上传会话有效期：未 PUT 完成的上传由清理器回收（转 failed + 删文件） */
  const MEDIA_UPLOAD_TTL_MS = 30 * 60_000;
  /** 服务端解包后的媒体过期时间：过期且未被消息占用的资产由 pruneMedia 回收 */
  const MEDIA_ASSET_TTL_MS = 30 * 24 * 3600_000;
  /** 并发上限：同一用户同时打开的 PUT 上传数（防单账号霸占磁盘/连接） */
  const MEDIA_MAX_CONCURRENT_UPLOADS = 3;
  /** 每用户未绑定资产上限（ready 未挂消息 + pending 未完成上传）：防“只上传不发送”刷盘 */
  const MEDIA_MAX_PENDING_ASSETS_PER_USER = 20;
  /** 每用户 1 小时内的 init 次数上限 */
  const MEDIA_MAX_INITS_PER_HOUR = 60;
  /** 单次 PUT 最长接收时间：慢速上传占着连接不放（服务端 requestTimeout 管整体） */
  const MEDIA_UPLOAD_TIMEOUT_MS = 10 * 60_000;

  /**
   * 媒体私有目录：与 SQLite 同锚（dbPath 的 data/ 下），不是工作区、永远不可代理。
   * 目录权限收紧到 0700（Windows 上忽略 mode，依赖父目录 ACL）。
   */
  const mediaRoot = path.join(path.dirname(dbPath), 'message-media');
  const mediaObjectsDir = path.join(mediaRoot, 'objects');
  const mediaTempDir = path.join(mediaRoot, 'tmp');
  for (const dir of [mediaRoot, mediaObjectsDir, mediaTempDir]) {
    try {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
    } catch (error) {
      console.warn('[dsh-passwords] 聊天媒体目录创建失败:', String(error));
    }
  }

  /**
   * storage key 的最终落盘路径。key 只由服务端随机生成（`o_<hex>` / `t_<hex>`），
   * 这里仍做一次白名单校验：任何含分隔符/点段/非白名单字符的键都拒绝，
   * 保证「随机 ID 决定路径」这条不变量在数据被污染时也不会被绕过。
   */
  const MEDIA_KEY_RE = /^[A-Za-z0-9_-]{8,128}$/;
  function mediaFilePath(key: string, subdir: 'objects' | 'tmp'): string {
    if (!MEDIA_KEY_RE.test(key)) throw new MediaError('存储键非法', 'INVALID_MEDIA');
    const base = subdir === 'objects' ? mediaObjectsDir : mediaTempDir;
    const full = path.join(base, key);
    // 纵深防御：拼接结果必须仍在目标目录内（key 白名单下恒成立）
    if (path.dirname(path.resolve(full)) !== path.resolve(base)) {
      throw new MediaError('存储键越界', 'INVALID_MEDIA');
    }
    return full;
  }

  function newMediaKey(prefix: string): string {
    return `${prefix}${randomBytes(16).toString('hex')}`;
  }

  function mediaKindOf(value: unknown): ChatMediaKind | null {
    return value === 'sticker' || value === 'image' || value === 'video' ? value : null;
  }

  /**
   * 魔数判定：只认文件真实内容，不认 Content-Type 声明（两者不符即拒绝）。
   * 覆盖设计稿允许的全部格式，并显式拒绝 SVG/HTML/XML/压缩包/可执行文件——
   * 它们要么魔数不匹配、要么（SVG/HTML/XML）被 isDangerousUploadName 拦下。
   */
  function sniffMediaType(head: Buffer): string | null {
    if (head.length < 12) return null;
    // JPEG: FF D8 FF
    if (head[0] === 0xff && head[1] === 0xd8 && head[2] === 0xff) return 'image/jpeg';
    // PNG: 89 50 4E 47 0D 0A 1A 0A
    if (head.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) {
      return 'image/png';
    }
    // GIF87a / GIF89a
    const gif = head.subarray(0, 6).toString('latin1');
    if (gif === 'GIF87a' || gif === 'GIF89a') return 'image/gif';
    // WebP: 'RIFF' + 4 字节长度 + 'WEBP'
    if (head.subarray(0, 4).toString('latin1') === 'RIFF' && head.subarray(8, 12).toString('latin1') === 'WEBP') {
      return 'image/webp';
    }
    // WebM: EBML 头 1A 45 DF A3（不进一步解析 DocType，见下方 MP4 注释）
    if (head[0] === 0x1a && head[1] === 0x45 && head[2] === 0xdf && head[3] === 0xa3) return 'video/webm';
    // MP4/MOV 家族: box size(4) + 'ftyp'。只做容器识别，不解析 codec——
    // 这里的目标是「不是图片/脚本/压缩包」，不是内容审核。
    if (head.subarray(4, 8).toString('latin1') === 'ftyp') return 'video/mp4';
    return null;
  }

  /**
   * 上传超时/放弃后的清理：临时文件立即删除，DB 行转 failed（保留元数据供排障，
   * 但绝不再是 ready，无法被 /messages 绑定）。storage key 占位符由之后
   * pruneMedia 的 pending 分支回收。
   */
  function failMediaUpload(mediaId: string, tempKey: string | null): void {
    if (tempKey !== null) {
      try {
        unlinkSync(mediaFilePath(tempKey, 'tmp'));
      } catch {
        /* 已删除或从未创建 */
      }
    }
    try {
      db.markMediaFailed(mediaId);
    } catch (error) {
      console.warn('[dsh-passwords] 媒体上传失败标记丢失:', String(error));
    }
  }

  /** 删除一批 storage keys 对应的文件本体（清理钩子用；失败只告警不阻断） */
  function unlinkMediaFiles(keys: readonly string[], subdir: 'objects' | 'tmp' = 'objects'): void {
    for (const key of keys) {
      if (key === '') continue;
      try {
        unlinkSync(mediaFilePath(key, subdir));
      } catch {
        /* 文件不存在（重复清理）或键非法：忽略 */
      }
    }
  }

  /**
   * 回收未被 DB 引用的临时上传文件：进程崩溃/重启会留下 tmp 文件（来不及 unlink），
   * DB 里已无对应行可参考，只能按 mtime 判断。保守取 4 倍上传 TTL，
   * 避免误删重启后仍可能被恢复的上传。
   */
  function pruneStaleMediaTemps(now: number): void {
    const cutoff = now - MEDIA_UPLOAD_TTL_MS * 4;
    let names: string[];
    try {
      names = readdirSync(mediaTempDir);
    } catch {
      return;
    }
    for (const name of names) {
      if (!MEDIA_KEY_RE.test(name)) continue;
      const full = path.join(mediaTempDir, name);
      try {
        if (statSync(full).mtimeMs < cutoff) unlinkSync(full);
      } catch {
        /* 已被其他清理路径删除 */
      }
    }
  }

  /** init 限流：每用户滑动窗口（内存面与活跃用户数成正比，由 sweep 周期裁剪） */
  const mediaInitRate = new Map<number, number[]>();
  /** 每用户正在进行的 PUT 上传数 */
  const mediaActiveUploads = new Map<number, number>();

  /** 子用户是否有聊天媒体权限（默认拒绝；主用户不受限） */
  function chatMediaAllowed(role: 'admin' | 'user', userId: number): boolean {
    if (role === 'admin') return true;
    return effectivePermissions(userId).allow_chat_media === true;
  }

  /** 标题式错误响应（所有媒体端点统一形状：{ ok:false, code, error }） */
  function mediaError(res: Response, status: number, code: string, message: string): void {
    res.status(status).json({ ok: false, code, error: message });
  }

  /**
   * 媒体读取的统一收尾。源流错误按是否已发头分流；客户端中途断开（含被背压
   * pause 后 abort）时 `pipe` 只会 unpipe、不会销毁源流，被挂住的 ReadStream
   * 会永久占着 fd，因此必须订阅响应的 close，在【未写完】时显式 destroy。
   * 正常写完（Range/HEAD/全量）时 writableFinished 为 true，仍走 autoClose
   * 关 fd 的既有路径，行为不变。
   */
  function pipeMedia(stream: ReadStream, res: Response): void {
    stream.on('error', () => {
      if (!res.headersSent) mediaError(res, 500, 'INTERNAL', '读取失败');
      else res.destroy();
    });
    res.once('close', () => {
      if (!res.writableFinished) stream.destroy();
    });
    stream.pipe(res);
  }

  /**
   * 上传端点的提前拒绝：在未读完整请求体时就回响应会让 Node 直接断开连接
   * （客户端看到 ECONNRESET 而非我们的 4xx/JSON）。先把请求体排空再响应，
   * 保证错误能完整送达；排空是丢弃性的，不再写入磁盘。
   * 同时清理临时文件并把 DB 行转 failed，不留下 ready 的半成品。
   */
  function rejectUpload(
    req: Request,
    res: Response,
    mediaId: string | null,
    tempKey: string | null,
    status: number,
    code: string,
    message: string,
  ): void {
    if (mediaId !== null) failMediaUpload(mediaId, tempKey);
    req.resume();
    // 'end' 在收到完整请求体（或被 aborted）后触发；'close' 兼容中断场景。
    let done = false;
    const respond = (): void => {
      if (done) return;
      done = true;
      mediaError(res, status, code, message);
    };
    req.once('end', respond);
    req.once('close', respond);
    // 兜底：客户端声明了 Content-Length 却迟迟不发（或已发送完毕但事件已错过）时
    // 不能永远挂着；短延迟后直接响应，此时连接已可安全关闭。
    const timer = setTimeout(respond, 1000);
    timer.unref();
  }

  /**
   * 签发上传：校验权限/类型/文件名/配额，落一行 pending 资产并返回不透明 IDs。
   * 只要客户端不提交 PUT，就不会占用磁盘（仅占一行元数据，由清理器回收）。
   */
  app.post('/gateway/api/message-media/init', jsonBody, (req, res) => {
    const me = apiAuth(req, res);
    if (!me) return;
    if (!chatMediaAllowed(me.role, me.userId)) {
      mediaError(res, 403, 'FORBIDDEN', '未开启聊天媒体权限');
      return;
    }
    const body = (req.body ?? {}) as Record<string, unknown>;
    const kind = mediaKindOf(body.kind);
    if (kind === null) {
      mediaError(res, 400, 'INVALID_KIND', 'kind 必须是 sticker/image/video');
      return;
    }
    // 文件名只作展示元数据，从不参与落盘路径；仍拒绝危险名（.. 与可执行/脚本/
    // SVG 后缀）以避免展示层/下载层对原始名的二次消费被利用。
    const rawName = typeof body.fileName === 'string' ? body.fileName : '';
    if (rawName !== '' && (rawName.length > 255 || isDangerousUploadName(rawName))) {
      mediaError(res, 400, 'INVALID_NAME', '文件名非法');
      return;
    }
    const policy = MEDIA_POLICY[kind];
    const declaredMime = typeof body.mimeType === 'string' ? body.mimeType.trim().toLowerCase() : '';
    if (declaredMime !== '' && !policy.mimes.includes(declaredMime)) {
      mediaError(res, 400, 'INVALID_MIME', '该类型不允许此 MIME');
      return;
    }
    const declaredSize = body.byteSize === undefined ? null : Number(body.byteSize);
    if (declaredSize !== null && (!Number.isSafeInteger(declaredSize) || declaredSize <= 0 || declaredSize > policy.maxBytes)) {
      mediaError(res, 400, 'TOO_LARGE', '文件过大');
      return;
    }
    // 限流：防脚本化刷 init 制造大量 pending 行
    const now = Date.now();
    const recent = (mediaInitRate.get(me.userId) ?? []).filter((t) => now - t < 3600_000);
    if (recent.length >= MEDIA_MAX_INITS_PER_HOUR) {
      mediaInitRate.set(me.userId, recent);
      mediaError(res, 429, 'RATE_LIMITED', '上传过于频繁，请稍后再试');
      return;
    }
    recent.push(now);
    mediaInitRate.set(me.userId, recent);
    // 配额：未绑定到消息的资产数量（pending 未完成上传 + ready 未挂消息）。
    // 已出现在 message_media 绑定表里的媒体不再占配额，否则正常聊天累计发送到上限后
    // 就会发起不了新的 init；pending 同期计入，防止只 init 不 PUT 绕过配额。
    const unbound = db.countUnboundMediaForUser(me.userId);
    if (unbound >= MEDIA_MAX_PENDING_ASSETS_PER_USER) {
      mediaError(res, 429, 'MEDIA_QUOTA', '未发送的媒体过多，请先发送或等待过期');
      return;
    }
    if ((mediaActiveUploads.get(me.userId) ?? 0) >= MEDIA_MAX_CONCURRENT_UPLOADS) {
      mediaError(res, 429, 'MEDIA_BUSY', '并发上传过多，请稍后再试');
      return;
    }
    const mediaId = newMediaKey('m_');
    const expiresAt = new Date(now + MEDIA_UPLOAD_TTL_MS);
    try {
      const created = db.addMediaAsset({
        id: mediaId,
        ownerId: me.userId,
        // pending 阶段不落盘：storage key 留空，由数据层写入占位键
        storageKey: '',
        originalName: rawName,
        kind,
        mimeType: declaredMime === '' ? policy.mimes[0] : declaredMime,
        byteSize: declaredSize ?? policy.maxBytes,
        sha256: '',
        state: 'pending',
        expiresAt,
      });
      if (!created.created) {
        mediaError(res, 409, 'MEDIA_CONFLICT', '上传标识冲突，请重试');
        return;
      }
    } catch (error) {
      console.warn('[dsh-passwords] 媒体元数据创建失败:', String(error));
      mediaError(res, 500, 'INTERNAL', '上传初始化失败');
      return;
    }
    res.json({
      ok: true,
      // uploadId 与 mediaId 当前同值：前者用于 PUT，后者用于消息绑定；
      // 分开给出是为将来把上传令牌与媒体身份解耦留口子，客户端不应假设二者不同。
      uploadId: mediaId,
      mediaId,
      kind,
      maxBytes: policy.maxBytes,
      allowedMimeTypes: policy.mimes,
      expiresAt: expiresAt.toISOString(),
    });
  });

  /**
   * 接收媒体二进制（流式落地，不经过 express JSON 解析）。
   * 安全要点（按顺序）：
   *   1. 鉴权 + 媒体权限；只有自己的 pending 资产可写；
   *   2. Content-Length 提前拒绝（不读一个字节）；实际字节数再按上限二次封口；
   *   3. 写入 temp 目录的随机文件名（绝不使用客户端提供的键/名），边写边算 sha256；
   *   4. 只有首块前 64 字节做魔数嗅探，与声明 MIME 必须一致；
   *   5. 全部通过才 rename 进 objects/ 并 finalizeMediaAsset；任何失败清理临时文件
   *      并把 DB 行转 failed（不留下 ready 的半成品）。
   */
  app.put('/gateway/api/message-media/:id', (req, res) => {
    const me = apiAuth(req, res);
    if (!me) return;
    const mediaId = typeof req.params.id === 'string' ? req.params.id : '';
    // 必须先做形状校验再入 DB：非法 ID 直接 404（不暴露“是否存在”的差异）
    if (!/^[A-Za-z0-9_-]{8,128}$/.test(mediaId)) {
      mediaError(res, 404, 'NOT_FOUND', '媒体不存在');
      return;
    }
    // 该 ID 必须是本用户的 pending 资产；否则一律 404（IDOR 防护：他人 ID 与
    // 不存在的 ID 返回同一个响应，不泄露媒体存在性）
    const asset = db.getMediaAssetFile(mediaId);
    if (!asset || asset.owner_id !== me.userId || asset.state !== 'pending') {
      mediaError(res, 404, 'NOT_FOUND', '媒体不存在');
      return;
    }
    // 权限在 PUT 时重判：init 后权限被收紧也要立即失效
    if (!chatMediaAllowed(me.role, me.userId)) {
      rejectUpload(req, res, mediaId, null, 403, 'FORBIDDEN', '未开启聊天媒体权限');
      return;
    }
    const kind = mediaKindOf(asset.kind);
    if (kind === null) {
      rejectUpload(req, res, mediaId, null, 400, 'INVALID_KIND', '媒体类型非法');
      return;
    }
    const policy = MEDIA_POLICY[kind];
    const declaredLength = Number(req.headers['content-length']);
    if (Number.isFinite(declaredLength) && declaredLength > policy.maxBytes) {
      rejectUpload(req, res, mediaId, null, 413, 'TOO_LARGE', '文件过大');
      return;
    }
    // Content-Type 若给出必须属于该类型白名单；空则由魔数决定
    const contentType = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
    if (contentType !== '' && !policy.mimes.includes(contentType)) {
      rejectUpload(req, res, mediaId, null, 415, 'INVALID_MIME', '该类型不允许此 MIME');
      return;
    }
    // 并发准入：与 init 共用同一计数，但必须在这里再判一次。init 只能拦住
    // 「有 PUT 正在进行」时的新签发；客户端仍可先签发足量 pending 资产，再同时
    // 打开全部 PUT，绕过「同一用户同时打开的 PUT 上传数」这一不变式。超限时
    // 不标记资产失败（传 mediaId=null）：这是可重试的背压，客户端应在其它上传
    // 结束后重发同一 uploadId，而不是被迫重新 init。
    if ((mediaActiveUploads.get(me.userId) ?? 0) >= MEDIA_MAX_CONCURRENT_UPLOADS) {
      rejectUpload(req, res, null, null, 429, 'MEDIA_BUSY', '并发上传过多，请稍后再试');
      return;
    }
    const tempKey = newMediaKey('u_');
    let tempPath: string;
    try {
      tempPath = mediaFilePath(tempKey, 'tmp');
    } catch {
      rejectUpload(req, res, mediaId, null, 500, 'INTERNAL', '上传初始化失败');
      return;
    }
    const hash = createHash('sha256');
    const out = createWriteStream(tempPath, { flags: 'wx', mode: 0o600 });
    let received = 0;
    let head: Buffer = Buffer.alloc(0);
    let settled = false;
    mediaActiveUploads.set(me.userId, (mediaActiveUploads.get(me.userId) ?? 0) + 1);
    const releaseSlot = (): void => {
      const current = (mediaActiveUploads.get(me.userId) ?? 1) - 1;
      if (current > 0) mediaActiveUploads.set(me.userId, current);
      else mediaActiveUploads.delete(me.userId);
    };
    const finishFailure = (status: number, code: string, message: string): void => {
      if (settled) return;
      settled = true;
      clearTimeout(uploadTimeout);
      releaseSlot();
      req.unpipe(out);
      out.destroy();
      failMediaUpload(mediaId, tempKey);
      if (!res.headersSent) {
        // 不 destroy 连接：排空剩余请求体后再回 4xx，让客户端能完整收到错误
        // （直接断开会把错误响应变成 ECONNRESET，客户端看不到原因）。
        // 数据事件已通过 settled 短路，字节不再落盘。
        rejectUpload(req, res, null, null, status, code, message);
        return;
      }
      req.resume();
    };
    const finishSuccess = (): void => {
      if (settled) return;
      settled = true;
      clearTimeout(uploadTimeout);
      releaseSlot();
      const objectKey = newMediaKey('o_');
      let objectPath: string;
      try {
        objectPath = mediaFilePath(objectKey, 'objects');
        // 原子转正：先把临时文件重命名进私有对象目录，再更新 DB。
        // 顺序保证「DB 说 ready」时文件必然已就位（反过来会留下不可读的 ready 记录）。
        renameSync(tempPath, objectPath);
      } catch (error) {
        console.warn('[dsh-passwords] 媒体转正失败:', String(error));
        failMediaUpload(mediaId, tempKey);
        mediaError(res, 500, 'INTERNAL', '媒体写入失败');
        return;
      }
      let finalized = null;
      try {
        finalized = db.finalizeMediaAsset(mediaId, {
          storageKey: objectKey,
          sha256: hash.digest('hex'),
          byteSize: received,
          mimeType: sniffed ?? asset.mime_type,
          expiresAt: new Date(Date.now() + MEDIA_ASSET_TTL_MS),
        });
      } catch (error) {
        console.warn('[dsh-passwords] 媒体元数据提交失败:', String(error));
      }
      if (finalized === null) {
        // 元数据没转正（并发/过期/已失败）：对象文件立即回收，不能留下无主文件
        try {
          unlinkSync(objectPath);
        } catch {
          /* 已删除 */
        }
        mediaError(res, 409, 'MEDIA_STATE', '上传状态已失效，请重新上传');
        return;
      }
      res.json({
        ok: true,
        mediaId,
        kind,
        mimeType: sniffed ?? asset.mime_type,
        byteSize: received,
        expiresAt: finalized.expires_at,
      });
    };
    let sniffed: string | null = null;
    const uploadTimeout = setTimeout(() => finishFailure(408, 'UPLOAD_TIMEOUT', '上传超时'), MEDIA_UPLOAD_TIMEOUT_MS);
    uploadTimeout.unref();
    out.on('error', () => finishFailure(500, 'INTERNAL', '媒体写入失败'));
    req.on('aborted', () => finishFailure(499, 'UPLOAD_ABORTED', '上传已中断'));
    // ⚠ 不用 req.pipe(out)：本处理器已自行消费 data 事件（计数/嗅探/哈希）。
    // 同时 pipe 会让每个块被写两次（文件变成两倍大，且大小校验形同虚设）。
    req.on('data', (chunk: Buffer) => {
      if (settled) return;
      received += chunk.length;
      if (received > policy.maxBytes) {
        finishFailure(413, 'TOO_LARGE', '文件过大');
        return;
      }
      if (head.length < 64) {
        head = head.length === 0 ? Buffer.from(chunk) : Buffer.concat([head, chunk]);
      }
      hash.update(chunk);
      // 首块到达即校验魔数：不匹配立刻中断，不为伪造内容写完整文件
      if (sniffed === null && head.length >= 12) {
        sniffed = sniffMediaType(head);
        if (sniffed === null || !policy.mimes.includes(sniffed)) {
          finishFailure(415, 'INVALID_CONTENT', '文件内容与类型不符');
          return;
        }
      }
      if (!out.write(chunk)) req.pause();
    });
    out.on('drain', () => {
      if (!settled) req.resume();
    });
    req.on('end', () => {
      if (settled) return;
      // 空文件 / 未达嗅探门槛：一律拒绝（没有可识别的媒体内容）
      if (received === 0) {
        finishFailure(400, 'EMPTY_UPLOAD', '上传内容为空');
        return;
      }
      if (sniffed === null) sniffed = sniffMediaType(head);
      if (sniffed === null || !policy.mimes.includes(sniffed)) {
        finishFailure(415, 'INVALID_CONTENT', '文件内容与类型不符');
        return;
      }
      out.end(() => finishSuccess());
    });
    req.on('error', () => finishFailure(500, 'INTERNAL', '上传失败'));
  });

  /**
   * 媒体读取：鉴权链 = 不透明媒体 ID → 占用它的消息 → 当前用户是否可见该消息
   * （getMessageMediaForUser）。**不按媒体 owner 放行**——主用户/上传者如果看不到
   * 那条消息（例如子用户给第三人发的私信），同样 404，避免用 owner 身份绕过。
   * 文件侧：realpath + 敏感目录屏蔽 + O_NOFOLLOW + fstat 锁 fd（与 /api/download 同口径）。
   */
  function serveMessageMedia(req: Request, res: Response): void {
    const me = apiAuth(req, res);
    if (!me) return;
    const mediaId = typeof req.params.id === 'string' ? req.params.id : '';
    if (!/^[A-Za-z0-9_-]{8,128}$/.test(mediaId)) {
      mediaError(res, 404, 'NOT_FOUND', '媒体不存在');
      return;
    }
    // 消息可见性鉴权：拿不到就是不存在的媒体（不区分“无权限”与“不存在”）
    const visible = db.getMessageMediaForUser(mediaId, me.userId);
    if (!visible) {
      mediaError(res, 404, 'NOT_FOUND', '媒体不存在');
      return;
    }
    const internal = db.getMediaAssetFile(mediaId);
    if (!internal || internal.state !== 'ready') {
      mediaError(res, 404, 'NOT_FOUND', '媒体不存在');
      return;
    }
    const kind = mediaKindOf(internal.kind);
    if (kind === null) {
      mediaError(res, 404, 'NOT_FOUND', '媒体不存在');
      return;
    }
    let expectedPath: string;
    try {
      expectedPath = mediaFilePath(internal.storage_key, 'objects');
    } catch {
      mediaError(res, 404, 'NOT_FOUND', '媒体不存在');
      return;
    }
    // realpath 后再比对：防 storage_key 被替换成指向媒体目录之外的符号链接
    let real: string;
    try {
      real = realpathSync(expectedPath);
    } catch {
      mediaError(res, 404, 'NOT_FOUND', '媒体不存在');
      return;
    }
    const mediaRootReal = (() => {
      try {
        return realpathSync(mediaObjectsDir);
      } catch {
        return path.resolve(mediaObjectsDir);
      }
    })();
    if (real !== expectedPath && !real.startsWith(mediaRootReal + path.sep)) {
      mediaError(res, 403, 'FORBIDDEN', '媒体路径非法');
      return;
    }
    // 锁定 fd：后续 Range/HEAD/GET 都从同一 fd 读取，避免 stat 与打开之间被替换
    let fd: number;
    let st;
    try {
      const noFollow = process.platform === 'win32' ? 0 : (fsConstants.O_NOFOLLOW ?? 0);
      fd = openSync(real, fsConstants.O_RDONLY | noFollow);
      st = fstatSync(fd);
    } catch {
      mediaError(res, 404, 'NOT_FOUND', '媒体不存在');
      return;
    }
    if (!st.isFile()) {
      closeSync(fd);
      mediaError(res, 404, 'NOT_FOUND', '媒体不存在');
      return;
    }
    const size = st.size;
    res.setHeader('Content-Type', internal.mime_type);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'private, no-store');
    // 只有视频实现了 Range（见下方分支）；图片/表情包带 Range 头也只会得到 200 全量。
    // 对不实现 Range 的类型声明 Accept-Ranges: bytes 会让下载器/代理误以为支持
    // 断点续传（RFC 9110 §14.5.1），因此仅对视频声明。
    if (kind === 'video') res.setHeader('Accept-Ranges', 'bytes');
    // inline：媒体要在消息气泡里直接渲染；文件名不参与（不输出原始名）
    res.setHeader('Content-Disposition', 'inline');
    const rangeHeader = typeof req.headers.range === 'string' ? req.headers.range : '';
    // Range 只对视频开放（图片/表情包不需要断点续传，少一条攻击面）
    if (kind === 'video' && rangeHeader !== '') {
      const match = /^bytes=([0-9]*)-([0-9]*)$/.exec(rangeHeader.trim());
      const invalid = (): void => {
        res.setHeader('Content-Range', `bytes */${size}`);
        closeSync(fd);
        res.status(416).end();
      };
      if (match === null) {
        invalid();
        return;
      }
      const startRaw = match[1];
      const endRaw = match[2];
      let start: number;
      let end: number;
      if (startRaw === '') {
        // 后缀范围 `bytes=-N`：取末尾 N 字节
        const suffix = endRaw === '' ? NaN : Number(endRaw);
        if (!Number.isSafeInteger(suffix) || suffix <= 0) {
          invalid();
          return;
        }
        start = Math.max(0, size - suffix);
        end = size - 1;
      } else {
        start = Number(startRaw);
        end = endRaw === '' ? size - 1 : Number(endRaw);
      }
      if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start > end || start >= size) {
        invalid();
        return;
      }
      if (end >= size) end = size - 1;
      res.status(206);
      res.setHeader('Content-Range', `bytes ${start}-${end}/${size}`);
      res.setHeader('Content-Length', String(end - start + 1));
      if (req.method === 'HEAD') {
        closeSync(fd);
        res.end();
        return;
      }
      pipeMedia(createReadStream(real, { fd, autoClose: true, start, end }), res);
      return;
    }
    res.setHeader('Content-Length', String(size));
    if (req.method === 'HEAD') {
      closeSync(fd);
      res.end();
      return;
    }
    pipeMedia(createReadStream(real, { fd, autoClose: true }), res);
  }

  app.get('/gateway/api/message-media/:id', serveMessageMedia);
  app.head('/gateway/api/message-media/:id', serveMessageMedia);

  /**
   * 周期清理之一：裁剪 init 限流滑动窗口（内存面与活跃用户数成正比）。
   * 网关在原 mediaInitRate 循环的位置调用，保证与 sweepMedia 的相对时序不变。
   */
  function sweepRate(now: number): void {
    for (const [userId, timestamps] of mediaInitRate) {
      const keep = timestamps.filter((t) => now - t < 3600_000);
      if (keep.length > 0) mediaInitRate.set(userId, keep);
      else mediaInitRate.delete(userId);
    }
  }

  /**
   * 周期清理之二：接回网关每 10 分钟的 sweep（位于 cap 段之后，与迁移前一致）。
   *   1. 过期资产 + 长期未提交的 pending 上传（DB 只删元数据，文件本体按键删除）；
   *   2. 消费消息历史修剪/clearMessages 在数据库事务内留下的待回收队列；
   *   3. 意外中断的 PUT 留下的临时文件（进程崩溃时来不及清理）。
   * 媒体清理失败只告警，不打断网关清理循环（与迁移前一致）。
   */
  function sweepMedia(now: number): void {
    // pendingCutoff 取 2 倍上传 TTL，避免误删正在进行中的上传。
    try {
      const mediaPlan = db.pruneMedia({
        now: new Date(now),
        pendingCutoff: new Date(now - MEDIA_UPLOAD_TTL_MS * 2),
      });
      unlinkMediaFiles(mediaPlan.storage_keys);
      // 消费消息历史修剪/clearMessages 在数据库事务内留下的待回收队列。
      // 读取并删除队列是同一事务，多个清理调用方不会重复领取同一 key。
      unlinkMediaFiles(db.drainPendingMediaRemovals());
      // 意外中断的 PUT 留下的临时文件（进程崩溃时来不及清理）
      pruneStaleMediaTemps(now);
    } catch (error) {
      console.warn('[dsh-passwords] 媒体清理失败:', String(error));
    }
  }

  return { chatMediaAllowed, sweepRate, sweepMedia };
}
