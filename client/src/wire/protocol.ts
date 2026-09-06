/**
 * The Hotline-ng wire, in TypeScript.
 *
 * This file is the client-side twin of `crates/hxd-ng-session/src/proto.rs`
 * and the spec it implements, `docs/hotline-ng.md` §5–§7 plus the voice
 * (`docs/voice.md` §8) and video (`docs/capabilities-video.md`) bindings.
 * When the server's shapes change, this is the file that changes with it —
 * nothing below `wire/` should ever hand-roll a frame.
 *
 * Three envelope shapes, discriminated by their first key: a request
 * carries `id`, a reply `reply`, an event `seq`.
 */

// --- Envelopes ----------------------------------------------------------

export interface ReqFrame {
  id: number;
  req: string;
  params: unknown;
}

export interface ReplyFrame {
  reply: number;
  ok?: unknown;
  error?: WireError;
}

export interface EventFrame {
  seq: number;
  ev: string;
  data: unknown;
}

export interface WireError {
  code: string;
  text: string;
}

export type ServerFrame = ReplyFrame | EventFrame;

export function isReply(f: ServerFrame): f is ReplyFrame {
  return (f as ReplyFrame).reply !== undefined;
}

export function isEvent(f: ServerFrame): f is EventFrame {
  return (f as EventFrame).seq !== undefined;
}

// --- Shared shapes ------------------------------------------------------

/** Presence, as §2's table defines it. `idle` and `detached` both show as
 *  the away colour to a 1.x client; only ng clients can tell them apart. */
export type Status = 'active' | 'idle' | 'detached';

export interface User {
  uid: number;
  nick: string;
  icon: number;
  admin: boolean;
  status: Status;
}

/** The `from` object on chat, msg and broadcast events: a uid and the
 *  nick as it stood when the line was sent, which is deliberately not the
 *  same thing as the roster's current nick. */
export interface Sender {
  uid: number;
  nick: string;
}

export interface ServerInfo {
  name: string;
  subject: string;
  agreement?: string;
}

export type ChatStyle = 'normal' | 'action';

// --- Handshake ----------------------------------------------------------

export interface LoginParams {
  login?: string;
  password?: string;
  nick?: string;
  icon?: number;
}

export interface VideoLimits {
  max_width: number;
  max_height: number;
  max_fps: number;
  max_bitrate: number;
  max_per_room: number;
}

export interface VideoConfig {
  camera: VideoLimits;
  screen: VideoLimits;
}

export interface LoginOk {
  session: string;
  token: string;
  self: User;
  server: ServerInfo;
  users: User[];
  /** `null` when this account may not detach — a resume will never
   *  succeed, so the client must log in again rather than try. */
  detach: { grace: number } | null;
  caps: string[];
  seq: number;
  /** Present only when the server offers video. */
  video?: VideoConfig;
}

export interface ResumeParams {
  session: string;
  token: string;
  last_seq: number;
}

export interface ResumeOk {
  replay: number;
  self: User;
}

export interface SyncOk {
  server: ServerInfo;
  users: User[];
  seq: number;
}

// --- Voice --------------------------------------------------------------

export interface VoiceParticipant {
  uid: number;
  muted: boolean;
}

export interface VoiceJoinOk {
  cid: number;
  sdp: string;
  codec: string;
  participants: VoiceParticipant[];
}

// --- Video --------------------------------------------------------------

export type VideoKind = 'camera' | 'screen';

export interface VideoPublication {
  uid: number;
  kind: VideoKind;
  paused: boolean;
}

export interface VideoStreamRef {
  uid: number;
  kind: VideoKind;
}

// --- Events -------------------------------------------------------------

export interface Events {
  user_joined: { user: User };
  user_changed: { user: User };
  user_parted: { uid: number };
  chat: { from: Sender; text: string; style: ChatStyle };
  notice: { text: string };
  subject: { subject: string };
  msg: { from: Sender; text: string };
  broadcast: { from: Sender; text: string };
  kicked: Record<string, never>;
  voice_offer: { cid: number; sdp: string };
  voice_ice: { cid: number; candidate: RTCIceCandidateInit | null };
  voice_status: { cid: number; participants: VoiceParticipant[] };
  video_status: { cid: number; publishers: VideoPublication[] };
  /** The server's placeholder for a domain event this protocol revision
   *  has no mapping for. It exists so `seq` never has holes; a client's
   *  only correct response is to count it and move on. */
  unsupported: Record<string, never>;
}

export type EventName = keyof Events;

// --- Error codes --------------------------------------------------------

/** Reasons a login can be refused. Wrong account and wrong password are
 *  deliberately one code. */
export const LOGIN_ERRORS = ['login_failed', 'banned', 'server_full'] as const;

/**
 * `resync_required` is not a failure: the session is still alive and the
 * connection still attached, the gap in the outbox is just too big to
 * replay. The client follows with `sync` on the same socket.
 */
export const RESYNC_REQUIRED = 'resync_required';
export const SESSION_EXPIRED = 'session_expired';

/** Human wording for the codes a person can actually act on. Anything
 *  not listed falls back to the server's own `text`, which is always
 *  present and always meant for a human. */
export const ERROR_TEXT: Record<string, string> = {
  login_failed: 'That account and password did not match.',
  banned: 'This server has banned your address.',
  server_full: 'The server is full.',
  session_expired: 'Your session expired. Logging in again.',
  access_denied: 'You do not have permission to do that.',
  rate_limited: 'Slow down — the server is rate-limiting this connection.',
  not_logged_in: 'Not logged in.',
  unknown_method: 'This server is older than this client and does not know that request.',
  voice_disabled: 'This server does not offer voice chat.',
  video_disabled: 'This server does not offer video.',
  voice_full: 'That voice chat is full.',
  video_full: 'Someone else is already sharing. Ask them to stop first.',
};

export function errorText(e: WireError): string {
  return ERROR_TEXT[e.code] ?? e.text ?? e.code;
}
