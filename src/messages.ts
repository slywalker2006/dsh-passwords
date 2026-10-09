// 留言 / 消息 / SSE 广播路由模块。
//
// 本文件由 src/gateway.ts 机械拆分而来，逐字保留原有行为、路由注册顺序与错误口径：
//   - chatClients / broadcastMessage：原 gateway.ts L2938-L2954
//   - GET  /gateway/api/messages         ：原 gateway.ts L5579-L5600
//   - POST /gateway/api/messages（含 msgRate 滑动窗口限流）：原 gateway.ts L5602-L5755
//   - GET  /gateway/api/messages/stream  ：原 gateway.ts L5757-L5787
//   - msgRate 周期清理（sweep 段）        ：原 gateway.ts L8362-L8366 + L8393
//
// 状态（chatClients / msgRate）由 registerMessageRoutes 工厂创建并闭包持有；
// 工厂返回的 sweep() 供 gateway 原 setInterval 清理调用，避免状态泄漏到 gateway。
// 模块不 import './gateway.js'（无运行时循环依赖）：所有闭包绑定的辅助函数通过
// 依赖注入传入，纯函数从各自所属模块直接引入。
import type { Application, Request, RequestHandler, Response } from 'express';
import { MediaError, MEDIA_IN_USE, type MessageRow } from './db.js';
import { sanitizeText } from './permissions.js';

/** 鉴权结果（与 gateway 内 apiAuth / authedUser 的返回结构一致）。 */
export interface AuthUser {
  userId: number;
  username: string;
  role: 'admin' | 'user';
}

/** 统一 API 鉴权：跨站拒绝 + 会话校验 + 可选主用户门控。 */
export type ApiAuth = (req: Request, res: Response, requireAdmin?: boolean) => AuthUser | null;

/**
 * 聊天 SSE 单订阅者的写缓冲上限。
 * `res.write()` 在内部缓冲低于 highWaterMark 时返回 true，超过时返回 false；
 * 忽略该返回值（持续对慢客户端写）会让服务端缓冲无界增长。这里把「写返回 false 后
 * 累计未排空的字节」超过上限的订阅者直接断开——SSE 是实时推送，慢客户端重连后可经
 * `/gateway/api/messages?since=` 增量补齐，故丢弃比持有无界缓冲更安全。
 */
export const CHAT_SSE_MAX_PENDING_BYTES = 1 * 1024 * 1024;

/** 向单个聊天 SSE 订阅者写一帧；返回 false 表示该订阅者应被移除（已关闭或缓冲超限）。 */
export function pushChatSseFrame(
  client: { res: Pick<Response, 'write' | 'writableEnded' | 'destroyed' | 'destroy'>; pendingBytes: number },
  payload: string,
): boolean {
  if (client.res.writableEnded || client.res.destroyed) return false;
  let flushed: boolean;
  try {
    flushed = client.res.write(payload);
  } catch {
    return false;
  }
  if (flushed) {
    // 缓冲已在 highWaterMark 以下：下次写若背压，从零重新累计。
    client.pendingBytes = 0;
    return true;
  }
  client.pendingBytes += Buffer.byteLength(payload, 'utf8');
  if (client.pendingBytes <= CHAT_SSE_MAX_PENDING_BYTES) return true;
  client.res.destroy();
  return false;
}

/**
 * 本模块用到的 DB 最小面。gateway 的 Database 实例结构兼容，可直接传入；
 * 只声明这里真正调用的方法，避免与 db.ts 的具体类型耦合。
 */
export interface MessageDb {
  listMessagesForUser(userId: number, limit?: number): MessageRow[];
  listMessagesAfterForUser(userId: number, sinceId: number, limit?: number): MessageRow[];
  latestMessageIdForUser(userId: number): number | null;
  mediaOwnedByUser(id: string, userId: number): boolean;
  mediaAttachedToAnyMessage(id: string): boolean;
  findAdminId(): number | null;
  getUserById(id: number): { id: number; username: string; role: 'admin' | 'user' } | null;
  addMessageWithMedia(input: {
    senderId: number;
    recipientId: number | null;
    content: string;
    tags: string[];
    mediaIds?: readonly string[];
    mediaCaptions?: readonly (string | null)[];
  }): MessageRow;
}

/** 依赖注入面：闭包绑定、随调用方生命周期存在的引用。 */
export interface MessageRouteDeps {
  db: MessageDb;
  /** gateway 闭包内的统一 API 鉴权（跨站/会话/可选主用户门控）。 */
  apiAuth: ApiAuth;
  /** gateway 的 express.json({ limit: '256kb' }) 中间件。 */
  jsonBody: RequestHandler;
  /** 子用户聊天媒体权限判定（主用户不受限）。 */
  chatMediaAllowed: (role: 'admin' | 'user', userId: number) => boolean;
  /** 严格非负整数解析。 */
  nullableInt: (v: unknown) => number | null;
  /** 字符串数组清洗（截断到 max）。 */
  stringArray: (v: unknown, max?: number) => string[];
  /**
   * 把长连接登记到网关共享撤销表（封禁/登出/删号/改密/权限变更时由网关关闭）。
   * 返回注销函数；重复调用幂等。未登记的长连接在撤权后仍会继续推送（撤权窗口）。
   */
  registerRevocableClient: (
    userId: number,
    client: { close: (code?: number, reason?: string) => void },
  ) => () => void;
}

/** 注册结果：工厂持有的状态清理钩子。 */
export interface MessageRoutes {
  /** 周期清理 msgRate（滑动窗口裁剪 + 容量裁剪），语义与 gateway 原 sweep 的 msgRate 段一致。 */
  sweep(): void;
}

export function registerMessageRoutes(app: Application, deps: MessageRouteDeps): MessageRoutes {
  const { db, apiAuth, jsonBody, chatMediaAllowed, nullableInt, stringArray, registerRevocableClient } = deps;

  // ── 留言 / 聊天（SSE 广播） ────────────────────────────────
  // 订阅者带 userId，广播时按收件人过滤（与 GET /gateway/api/messages 的
  // 列表语义一致）：定向消息只推给收件人与发件人，公开消息推给所有人。
  interface ChatClient {
    res: Response;
    userId: number;
    /** 写背压后累计的未排空字节（见 pushChatSseFrame / CHAT_SSE_MAX_PENDING_BYTES）。 */
    pendingBytes: number;
  }
  const chatClients = new Set<ChatClient>();
  function broadcastMessage(msg: MessageRow): void {
    const payload = `data: ${JSON.stringify(msg)}\n\n`;
    for (const client of chatClients) {
      const visible =
        msg.recipient_id === null || msg.recipient_id === client.userId || msg.sender_id === client.userId;
      if (!visible) continue;
      if (!pushChatSseFrame(client, payload)) chatClients.delete(client);
    }
  }

  // ── 留言列表（所有登录用户；可见性在 SQL 层按用户过滤） ─────
  // 支持 ?since=<id> 增量拉取（客户端轮询只取新增消息，避免每次全量下载）。
  // reset：游标超前于【当前用户可见】的最新 id（数据库重建/消息清空后自增从头
  // 开始）时，服务端回退全量并显式告知客户端重建基线——只靠客户端“空响应”判断
  // 无法区分“正常无新消息”与“游标已失效”，会永久收不到新消息。
  // 不能用全局最大 id：既泄露全平台消息活动量，也会被其他用户私信干扰判定。
  app.get('/gateway/api/messages', (req, res) => {
    const me = apiAuth(req, res);
    if (!me) return;
    const sinceRaw = typeof req.query.since === 'string' ? Number(req.query.since) : NaN;
    const since = Number.isFinite(sinceRaw) && sinceRaw > 0 ? Math.floor(sinceRaw) : 0;
    let mine = since > 0 ? db.listMessagesAfterForUser(me.userId, since, 300) : db.listMessagesForUser(me.userId, 300);
    let reset = false;
    if (since > 0 && mine.length === 0) {
      const latest = db.latestMessageIdForUser(me.userId);
      if (latest === null || since > latest) {
        reset = true;
        mine = db.listMessagesForUser(me.userId, 300);
      }
    }
    res.json({ ok: true, me: { id: me.userId, username: me.username, role: me.role }, messages: mine, reset });
  });

  // ── 发送留言（所有登录用户） ─────────────────────────────────
  // F-22：留言洪泛限流——每用户 60 秒内最多 12 条（滑动窗口），防止刷爆广播栏。
  const msgRate = new Map<number, number[]>();
  app.post('/gateway/api/messages', jsonBody, (req, res) => {
    const me = apiAuth(req, res);
    if (!me) return;
    const now = Date.now();
    const recent = (msgRate.get(me.userId) ?? []).filter((t) => now - t < 60_000);
    if (recent.length >= 12) {
      msgRate.set(me.userId, recent);
      res.status(429).json({ ok: false, code: 'RATE_LIMITED', error: '留言过于频繁，请稍后再试' });
      return;
    }
    recent.push(now);
    msgRate.set(me.userId, recent);
    const body = (req.body ?? {}) as Record<string, unknown>;
    // 服务端净化（#3）：剥离 HTML/CSS 结构后入库——防存储型注入 + AI agent 间接提示注入
    const content = sanitizeText(typeof body.content === 'string' ? body.content : '');
    // 媒体附件：纯媒体消息允许 content 为空，但必须至少有一个合法媒体
    // （见下方「必需条件」判定）。mediaIds 是客户端拿到的不透明 ID 数组。
    const rawMediaIds = Array.isArray(body.mediaIds) ? body.mediaIds : [];
    if (
      rawMediaIds.length > 10 ||
      rawMediaIds.some((id) => typeof id !== 'string' || !/^[A-Za-z0-9_-]{8,128}$/.test(id))
    ) {
      res.status(400).json({ ok: false, code: 'INVALID_MEDIA_ID', error: '媒体 ID 非法' });
      return;
    }
    const mediaIds = [...new Set(rawMediaIds as string[])];
    if (mediaIds.length > 0 && !chatMediaAllowed(me.role, me.userId)) {
      res.status(403).json({ ok: false, code: 'FORBIDDEN', error: '未开启聊天媒体权限' });
      return;
    }
    const rawCaptions = Array.isArray(body.captions) ? body.captions : [];
    if (rawCaptions.some((caption) => caption !== null && typeof caption !== 'string')) {
      res.status(400).json({ ok: false, code: 'INVALID', error: 'captions 必须是字符串数组' });
      return;
    }
    // 发布前的预检（与数据层的绑定校验同口径）：失败在写库前给出明确 4xx，
    // 数据层仍在事务内重复校验（并发下它是唯一可信边界）。
    for (const mediaId of mediaIds) {
      if (!db.mediaOwnedByUser(mediaId, me.userId)) {
        res.status(403).json({ ok: false, code: 'MEDIA_NOT_OWNED', error: '媒体不属于当前用户或未就绪' });
        return;
      }
      if (db.mediaAttachedToAnyMessage(mediaId)) {
        res.status(409).json({ ok: false, code: 'MEDIA_IN_USE', error: '媒体已被其他消息占用' });
        return;
      }
    }
    if (content === '') {
      // 纯媒体消息：内容可以为空串，但必须有媒体；两者都缺仍按旧行为拒绝
      if (mediaIds.length === 0) {
        res.status(400).json({ ok: false, code: 'INVALID', error: '内容不能为空' });
        return;
      }
    }
    if (content.length > 4000) {
      res.status(400).json({ ok: false, code: 'INVALID', error: '内容过长' });
      return;
    }
    // 投递口径（Discussion #6 实施项 5）：
    //   1. recipientId 显式给出 → 私信该用户（主用户可私信任何人；子用户只能私信主用户）。
    //      非法值绝不静默归一成广播（调用方本意私信却公开发出 = 隐私事故）；
    //      不存在的用户也不能留下永远不可投递的孤儿消息（messages 无 FK）。
    //   2. broadcast === true → 广播；仅主用户可用（子用户广播会被拦下）。
    //   3. 两者都缺 → 子用户默认私信主用户（客服/反馈语义）；主用户必须显式
    //      选择收件人或勾选广播，避免误发全员消息。
    const rawRecipient = body.recipientId;
    const wantBroadcast = body.broadcast === true;
    // 一次取用：两个分支共用，避免两次查询间 admin 被删导致错误码口径漂移
    const adminId = db.findAdminId();
    let recipientId: number | null = null;
    if (rawRecipient !== undefined && rawRecipient !== null) {
      if (wantBroadcast) {
        // 两个意图互斥：同时给出视为歧义请求（主用户本想广播却被静默降级成私信 = 坏契约）
        res.status(400).json({ ok: false, code: 'INVALID', error: 'recipientId 与 broadcast 不能同时提供' });
        return;
      }
      recipientId = nullableInt(rawRecipient);
      if (recipientId === null || recipientId < 1) {
        res.status(400).json({ ok: false, code: 'INVALID', error: 'recipientId 无效' });
        return;
      }
      if (db.getUserById(recipientId) === null) {
        res.status(404).json({ ok: false, code: 'NO_SUCH_USER', error: '收件人不存在' });
        return;
      }
    } else if (wantBroadcast) {
      if (me.role !== 'admin') {
        res.status(403).json({ ok: false, code: 'FORBIDDEN_BROADCAST', error: '仅主用户可以发送广播消息' });
        return;
      }
    } else if (me.role !== 'admin') {
      if (adminId === null) {
        res.status(500).json({ ok: false, code: 'INTERNAL', error: '平台主用户缺失' });
        return;
      }
      recipientId = adminId;
    } else {
      res.status(400).json({ ok: false, code: 'SELECT_RECIPIENT', error: '请选择收件人或勾选广播' });
      return;
    }
    // 子用户只能私信主用户（跨子用户私信在多租户场景下无业务价值，且扩大消息泄露面）
    if (me.role !== 'admin' && recipientId !== null && (adminId === null || recipientId !== adminId)) {
      res.status(403).json({ ok: false, code: 'FORBIDDEN_RECIPIENT', error: '子用户只能给主用户发私信' });
      return;
    }
    // tag 是展示元数据：限制数量、逐项长度并去空白，防 256KB JSON 请求把极长 tag
    // 持久化到每条消息（content 已有 4k 上限）。保留未知短 tag 兼容旧数据/扩展。
    const tags = stringArray(body.tags)
      .map((tag) => tag.trim())
      .filter((tag) => tag.length > 0 && tag.length <= 64)
      .slice(0, 8);
    // captions 与 mediaIds 同序（数据层按索引写入 sort_order 对应的 caption）
    const mediaCaptions = mediaIds.map((_, index) => {
      const raw = rawCaptions[index];
      if (typeof raw !== 'string') return null;
      // caption 也是可渲染的展示文本：与 content 同口径净化
      const caption = sanitizeText(raw).trim();
      return caption === '' ? null : caption.slice(0, 500);
    });
    let msg: MessageRow;
    try {
      // 同一事务写入消息与媒体关系（媒体校验失败则消息不落库）
      msg = db.addMessageWithMedia({
        senderId: me.userId,
        recipientId,
        content,
        tags,
        mediaIds,
        mediaCaptions,
      });
    } catch (error) {
      if (error instanceof MediaError) {
        const status =
          error.code === 'MEDIA_NOT_OWNED' || error.code === 'MEDIA_NOT_READY' || error.code === 'MEDIA_EXPIRED'
            ? 403
            : error.code === MEDIA_IN_USE
              ? 409
              : error.code === 'MEDIA_NOT_FOUND' || error.code === 'INVALID_MEDIA_ID'
                ? 404
                : 400;
        res.status(status).json({ ok: false, code: error.code, error: '媒体附件无效' });
        return;
      }
      // 写库失败（磁盘/锁）：不能返回一个并不存在的消息
      console.warn('[dsh-passwords] 留言写入失败:', String(error));
      res.status(500).json({ ok: false, code: 'INTERNAL', error: '消息发送失败' });
      return;
    }
    broadcastMessage(msg);
    res.json({ ok: true, message: msg });
  });

  // ── SSE 实时推送（所有登录用户） ─────────────────────────────
  app.get('/gateway/api/messages/stream', (req, res) => {
    const me = apiAuth(req, res);
    if (!me) return;
    res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders();
    res.write(`data: ${JSON.stringify({ type: 'init', me: { id: me.userId, username: me.username, role: me.role } })}\n\n`);
    const client: ChatClient = { res, userId: me.userId, pendingBytes: 0 };
    chatClients.add(client);
    // 写背压恢复：一次 write 返回 true 即代表缓冲已回到 highWaterMark 以下。
    res.on('drain', () => { client.pendingBytes = 0; });
    // 登记到网关撤销表：封禁/登出/删号/改密/权限变更与 WS 同口径立即断开，
    // 不留「HTTP 已失效而 SSE 仍持续推送」的撤权窗口。
    const unregisterClient = registerRevocableClient(me.userId, {
      close: () => { if (!res.writableEnded) res.destroy(); },
    });
    // 心跳：25 秒一条 SSE 注释帧。既防止代理/负载均衡器把空闲连接杀掉，
    // 也用于探活——write 失败/缓冲超限说明连接已死或跟不上，立即移除。
    const heartbeat = setInterval(() => {
      if (!pushChatSseFrame(client, ': ping\n\n')) {
        clearInterval(heartbeat);
        chatClients.delete(client);
      }
    }, 25_000);
    heartbeat.unref();
    // req/res 双监听 close（断网无 FIN 时 res.close 兜底），清理幂等
    const cleanup = () => {
      clearInterval(heartbeat);
      chatClients.delete(client);
      unregisterClient();
    };
    req.on('close', cleanup);
    res.on('close', cleanup);
  });

  // ── 周期性清理（由 gateway 的 sweep 定时器调用） ─────────────
  // 与 gateway 原 sweep 的 cap 同口径：极端 key 洪泛下保留最新一半。
  const cap = <T>(map: Map<T, unknown>, limit = 10_000) => {
    if (map.size <= limit) return;
    let drop = Math.ceil(map.size / 2);
    for (const key of map.keys()) {
      map.delete(key);
      if (--drop === 0) break;
    }
  };
  function sweep(): void {
    const now = Date.now();
    for (const [k, v] of msgRate) {
      const keep = v.filter((t) => now - t < 60_000);
      if (keep.length > 0) msgRate.set(k, keep);
      else msgRate.delete(k);
    }
    cap(msgRate);
  }

  return { sweep };
}
