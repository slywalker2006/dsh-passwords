/**
 * Structured close diagnostics for the shared /api/remote.mux carrier.
 *
 * One physical carrier multiplexes every Remote stream (history, files,
 * terminal, events). When it tears down, operators need to know which leg
 * initiated it, a bounded cause, the close code, and the buffer/probe/stall
 * counters that were live at that moment. What they must never get is the raw
 * material: message bodies, cookies, JWTs, credentials, full URLs or the
 * unprocessed reason string the caller happened to pass.
 *
 * The core is a pure, immutable state object. Every transition returns a new
 * state, and the terminal record is latched: the first close wins, later calls
 * are no-ops. The emitted record contains only enum members and bounded
 * non-negative integers, each produced by a whitelist normalizer that degrades
 * unknown input to a reserved member instead of echoing it.
 *
 * `createRemoteMuxDiagnosticsSession` is the thin mutable handle the proxy
 * closure uses: one instance per carrier, observe buffers near the close site,
 * then call `close` once with the restricted source/direction/code.
 */

/** Restricted close-cause classification. */
export const REMOTE_MUX_CLOSE_SOURCES = [
  'client-close',
  'client-error',
  'upstream-close',
  'upstream-error',
  'heartbeat',
  'backpressure',
  'queue-overflow',
  'send-failed',
  'protocol',
  'permission-revoked',
  'shutdown',
  'unknown',
] as const;
export type RemoteMuxCloseSource = (typeof REMOTE_MUX_CLOSE_SOURCES)[number];

/** Which leg of the carrier the terminal event came from. */
export const REMOTE_MUX_DIRECTIONS = ['client', 'upstream', 'both'] as const;
export type RemoteMuxDirection = (typeof REMOTE_MUX_DIRECTIONS)[number];

/** Restricted close-code whitelist; 0 marks a code that is not representable. */
export const REMOTE_MUX_CLOSE_CODES = [0, 1000, 1001, 1002, 1003, 1006, 1008, 1009, 1011, 1012, 1013] as const;
export type RemoteMuxCloseCode = (typeof REMOTE_MUX_CLOSE_CODES)[number];

/** Latest observed ping/pong probe state. */
export const REMOTE_MUX_PROBE_STATES = ['idle', 'pending', 'responded', 'timeout'] as const;
export type RemoteMuxProbeState = (typeof REMOTE_MUX_PROBE_STATES)[number];

/** Latest observed stall class; `none` means progress was seen. */
export const REMOTE_MUX_STALL_KINDS = ['none', 'write', 'probe'] as const;
export type RemoteMuxStallKind = (typeof REMOTE_MUX_STALL_KINDS)[number];

/** 受限的 Sender 拒绝类别；只记录类别、方向和字节数，不记录正文。 */
export const REMOTE_MUX_REJECT_KINDS = ['message-bytes', 'accepted-bytes', 'queue-count', 'queue-bytes'] as const;
export type RemoteMuxRejectKind = (typeof REMOTE_MUX_REJECT_KINDS)[number];

export const REMOTE_MUX_SENDER_DIRECTIONS = ['client', 'upstream'] as const;
export type RemoteMuxSenderDirection = (typeof REMOTE_MUX_SENDER_DIRECTIONS)[number];

/**
 * Maps the reason strings the gateway already passes to its close helper (and
 * the identity/lifecycle reasons used when it revokes a user's carriers) onto
 * the restricted source enum. Anything unrecognized becomes `unknown`; the raw
 * text is discarded, never stored.
 */
const CLOSE_SOURCE_BY_REASON: ReadonlyMap<string, RemoteMuxCloseSource> = new Map([
  ['client websocket error', 'client-error'],
  ['Remote stream heartbeat timed out', 'heartbeat'],
  ['Remote stream heartbeat failed', 'heartbeat'],
  ['Remote stream queue too large', 'queue-overflow'],
  ['Remote stream send failed', 'send-failed'],
  ['Remote stream backpressure limit exceeded', 'backpressure'],
  ['text messages required', 'protocol'],
  ['invalid Remote stream request', 'protocol'],
  ['duplicate stream id', 'protocol'],
  ['too many Remote streams', 'protocol'],
  ['invalid Remote stream payload', 'protocol'],
  ['invalid Remote stream response', 'protocol'],
  ['upstream error', 'upstream-error'],
  ['upstream closed', 'upstream-close'],
  ['Permissions changed', 'permission-revoked'],
  ['Identity switched', 'permission-revoked'],
  ['Credentials changed', 'permission-revoked'],
  ['Session ended', 'permission-revoked'],
]);

/**
 * Opaque, generated carrier id (never derived from request data). A short
 * `[A-Za-z0-9._#-]` token passes; a URL-shaped value (a `scheme://`, a query
 * string, a path) or an over-long token collapses to a fixed placeholder, so a
 * mis-wired caller cannot smuggle a URL or a real credential-sized token into
 * the record via `carrier`. This is a charset+length bound, not JWT
 * fingerprinting: a short opaque id that happens to contain dots is allowed.
 */
const CARRIER_ID_RE = /^[A-Za-z0-9._#-]{1,64}$/;
const CARRIER_ID_FALLBACK = 'remote.mux';

/** Bounded non-negative integer; rejects NaN/Infinity/negatives to 0. */
export function normalizeRemoteMuxCounter(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return 0;
  return Math.trunc(Math.min(value, Number.MAX_SAFE_INTEGER));
}

export function normalizeRemoteMuxCarrierId(value: unknown): string {
  if (typeof value === 'string' && CARRIER_ID_RE.test(value)) return value;
  return CARRIER_ID_FALLBACK;
}

export function normalizeRemoteMuxCloseSource(value: unknown): RemoteMuxCloseSource {
  if (typeof value === 'string') {
    if ((REMOTE_MUX_CLOSE_SOURCES as readonly string[]).includes(value)) return value as RemoteMuxCloseSource;
    return CLOSE_SOURCE_BY_REASON.get(value) ?? 'unknown';
  }
  return 'unknown';
}

export function normalizeRemoteMuxDirection(value: unknown): RemoteMuxDirection {
  if (typeof value === 'string' && (REMOTE_MUX_DIRECTIONS as readonly string[]).includes(value)) {
    return value as RemoteMuxDirection;
  }
  return 'both';
}

export function normalizeRemoteMuxCloseCode(value: unknown): RemoteMuxCloseCode {
  if (typeof value === 'number' && (REMOTE_MUX_CLOSE_CODES as readonly number[]).includes(value)) {
    return value as RemoteMuxCloseCode;
  }
  return 0;
}

export function normalizeRemoteMuxProbeState(value: unknown): RemoteMuxProbeState {
  if (typeof value === 'string' && (REMOTE_MUX_PROBE_STATES as readonly string[]).includes(value)) {
    return value as RemoteMuxProbeState;
  }
  return 'idle';
}

export function normalizeRemoteMuxStallKind(value: unknown): RemoteMuxStallKind {
  if (typeof value === 'string' && (REMOTE_MUX_STALL_KINDS as readonly string[]).includes(value)) {
    return value as RemoteMuxStallKind;
  }
  return 'none';
}

/** The observations a caller can sample while the carrier is live. */
export interface RemoteMuxSenderObservation {
  readonly queuedMessages: unknown;
  readonly queuedBytes: unknown;
  readonly acceptedBytes: unknown;
  readonly inFlight: unknown;
  readonly bufferedAmount: unknown;
}

export interface RemoteMuxRejectObservation {
  readonly direction: unknown;
  readonly kind: unknown;
  readonly messageBytes: unknown;
}

export interface RemoteMuxCarrierObservation {
  readonly bufferedBytes: unknown;
  readonly pendingBytes: unknown;
  readonly streams: unknown;
  readonly probe: unknown;
  readonly probeElapsedMs: unknown;
  readonly stall: unknown;
  readonly stallElapsedMs: unknown;
  readonly clientSender?: Partial<RemoteMuxSenderObservation>;
  readonly upstreamSender?: Partial<RemoteMuxSenderObservation>;
  readonly reject?: Partial<RemoteMuxRejectObservation> | null;
}

/** Close input: the terminal observation plus the restricted classification. */
export type RemoteMuxCloseInput = Partial<RemoteMuxCarrierObservation> & {
  readonly source?: unknown;
  readonly direction?: unknown;
  readonly code?: unknown;
};

/** Terminal, privacy-safe record: enum members and bounded counters only. */
export interface RemoteMuxSenderRecord {
  readonly queuedMessages: number;
  readonly queuedBytes: number;
  readonly acceptedBytes: number;
  readonly inFlight: boolean;
  readonly bufferedAmount: number;
}

export interface RemoteMuxRejectRecord {
  readonly direction: RemoteMuxSenderDirection;
  readonly kind: RemoteMuxRejectKind;
  readonly messageBytes: number;
}

export interface RemoteMuxCloseRecord {
  readonly carrier: string;
  readonly source: RemoteMuxCloseSource;
  readonly direction: RemoteMuxDirection;
  readonly code: RemoteMuxCloseCode;
  readonly bufferedBytes: number;
  readonly pendingBytes: number;
  readonly streams: number;
  readonly probe: RemoteMuxProbeState;
  readonly probeElapsedMs: number;
  readonly stall: RemoteMuxStallKind;
  readonly stallElapsedMs: number;
  readonly clientSender: RemoteMuxSenderRecord;
  readonly upstreamSender: RemoteMuxSenderRecord;
  readonly reject: RemoteMuxRejectRecord | null;
}

/** Pure, immutable per-carrier diagnostics state. */
export interface RemoteMuxDiagnosticsState {
  readonly carrier: string;
  readonly bufferedBytes: number;
  readonly pendingBytes: number;
  readonly streams: number;
  readonly probe: RemoteMuxProbeState;
  readonly probeElapsedMs: number;
  readonly stall: RemoteMuxStallKind;
  readonly stallElapsedMs: number;
  readonly clientSender: RemoteMuxSenderRecord;
  readonly upstreamSender: RemoteMuxSenderRecord;
  readonly reject: RemoteMuxRejectRecord | null;
  /** Latched terminal record; the first `recordRemoteMuxClose` wins. */
  readonly close: RemoteMuxCloseRecord | null;
}

export function createRemoteMuxDiagnostics(carrier: unknown): RemoteMuxDiagnosticsState {
  return {
    carrier: normalizeRemoteMuxCarrierId(carrier),
    bufferedBytes: 0,
    pendingBytes: 0,
    streams: 0,
    probe: 'idle',
    probeElapsedMs: 0,
    stall: 'none',
    stallElapsedMs: 0,
    clientSender: { queuedMessages: 0, queuedBytes: 0, acceptedBytes: 0, inFlight: false, bufferedAmount: 0 },
    upstreamSender: { queuedMessages: 0, queuedBytes: 0, acceptedBytes: 0, inFlight: false, bufferedAmount: 0 },
    reject: null,
    close: null,
  };
}

/**
 * Pure observation update. Only keys present on `observation` change state;
 * an absent key keeps the previous sample. Returns a new state object.
 */
function normalizeSenderDirection(value: unknown): RemoteMuxSenderDirection {
  return typeof value === 'string' && (REMOTE_MUX_SENDER_DIRECTIONS as readonly string[]).includes(value)
    ? value as RemoteMuxSenderDirection
    : 'client';
}

function normalizeRejectKind(value: unknown): RemoteMuxRejectKind {
  return typeof value === 'string' && (REMOTE_MUX_REJECT_KINDS as readonly string[]).includes(value)
    ? value as RemoteMuxRejectKind
    : 'accepted-bytes';
}

function normalizeSenderObservation(
  value: Partial<RemoteMuxSenderObservation>,
  previous: RemoteMuxSenderRecord,
): RemoteMuxSenderRecord {
  return {
    queuedMessages: value.queuedMessages === undefined ? previous.queuedMessages : normalizeRemoteMuxCounter(value.queuedMessages),
    queuedBytes: value.queuedBytes === undefined ? previous.queuedBytes : normalizeRemoteMuxCounter(value.queuedBytes),
    acceptedBytes: value.acceptedBytes === undefined ? previous.acceptedBytes : normalizeRemoteMuxCounter(value.acceptedBytes),
    inFlight: value.inFlight === undefined ? previous.inFlight : value.inFlight === true,
    bufferedAmount: value.bufferedAmount === undefined ? previous.bufferedAmount : normalizeRemoteMuxCounter(value.bufferedAmount),
  };
}

function normalizeRejectObservation(value: Partial<RemoteMuxRejectObservation>): RemoteMuxRejectRecord {
  return {
    direction: normalizeSenderDirection(value.direction),
    kind: normalizeRejectKind(value.kind),
    messageBytes: normalizeRemoteMuxCounter(value.messageBytes),
  };
}

export function observeRemoteMuxCarrier(
  state: RemoteMuxDiagnosticsState,
  observation: Partial<RemoteMuxCarrierObservation>,
): RemoteMuxDiagnosticsState {
  return {
    ...state,
    bufferedBytes: observation.bufferedBytes === undefined ? state.bufferedBytes : normalizeRemoteMuxCounter(observation.bufferedBytes),
    pendingBytes: observation.pendingBytes === undefined ? state.pendingBytes : normalizeRemoteMuxCounter(observation.pendingBytes),
    streams: observation.streams === undefined ? state.streams : normalizeRemoteMuxCounter(observation.streams),
    probe: observation.probe === undefined ? state.probe : normalizeRemoteMuxProbeState(observation.probe),
    probeElapsedMs: observation.probeElapsedMs === undefined ? state.probeElapsedMs : normalizeRemoteMuxCounter(observation.probeElapsedMs),
    stall: observation.stall === undefined ? state.stall : normalizeRemoteMuxStallKind(observation.stall),
    stallElapsedMs: observation.stallElapsedMs === undefined ? state.stallElapsedMs : normalizeRemoteMuxCounter(observation.stallElapsedMs),
    clientSender: observation.clientSender === undefined ? state.clientSender : normalizeSenderObservation(observation.clientSender, state.clientSender),
    upstreamSender: observation.upstreamSender === undefined ? state.upstreamSender : normalizeSenderObservation(observation.upstreamSender, state.upstreamSender),
    reject: observation.reject === undefined
      ? state.reject
      : observation.reject === null
        ? null
        : normalizeRejectObservation(observation.reject),
  };
}

/**
 * Latches the terminal record once per carrier. The first call records the
 * close (merging any observations carried on `input`); every later call is a
 * no-op that returns the same state object.
 */
export function recordRemoteMuxClose(
  state: RemoteMuxDiagnosticsState,
  input: RemoteMuxCloseInput,
): RemoteMuxDiagnosticsState {
  if (state.close !== null) return state;
  const observed = observeRemoteMuxCarrier(state, input);
  return {
    ...observed,
    close: {
      carrier: observed.carrier,
      source: normalizeRemoteMuxCloseSource(input.source),
      direction: normalizeRemoteMuxDirection(input.direction),
      code: normalizeRemoteMuxCloseCode(input.code),
      bufferedBytes: observed.bufferedBytes,
      pendingBytes: observed.pendingBytes,
      streams: observed.streams,
      probe: observed.probe,
      probeElapsedMs: observed.probeElapsedMs,
      stall: observed.stall,
      stallElapsedMs: observed.stallElapsedMs,
      clientSender: observed.clientSender,
      upstreamSender: observed.upstreamSender,
      reject: observed.reject,
    },
  };
}

/** The latched record, or null while the carrier is still live. */
export function remoteMuxCloseLogRecord(state: RemoteMuxDiagnosticsState): RemoteMuxCloseRecord | null {
  return state.close;
}

/** Minimal handle the proxy closure keeps for the lifetime of one carrier. */
export interface RemoteMuxDiagnosticsSession {
  readonly carrier: string;
  /** Replace the live counters/probe/stall sample before closing. */
  observe(observation: Partial<RemoteMuxCarrierObservation>): void;
  /** Record the close once; returns the record on the first call, else null. */
  close(input: RemoteMuxCloseInput): RemoteMuxCloseRecord | null;
  /** The latched record, or null while the carrier is still live. */
  snapshot(): RemoteMuxCloseRecord | null;
}

export function createRemoteMuxDiagnosticsSession(carrier: unknown): RemoteMuxDiagnosticsSession {
  let state = createRemoteMuxDiagnostics(carrier);
  return {
    get carrier(): string {
      return state.carrier;
    },
    observe(observation: Partial<RemoteMuxCarrierObservation>): void {
      state = observeRemoteMuxCarrier(state, observation);
    },
    close(input: RemoteMuxCloseInput): RemoteMuxCloseRecord | null {
      const alreadyClosed = state.close !== null;
      state = recordRemoteMuxClose(state, input);
      return alreadyClosed ? null : state.close;
    },
    snapshot(): RemoteMuxCloseRecord | null {
      return state.close;
    },
  };
}
