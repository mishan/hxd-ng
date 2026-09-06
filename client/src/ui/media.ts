/**
 * Voice and video: one peer connection, one room, one SFU.
 *
 * The wire is `docs/voice.md` §8 and the Hotline-ng binding of
 * `docs/capabilities-video.md`. The rules that shape this file are the
 * server's, not the browser's:
 *
 * - **The server is always the offerer.** There is exactly one
 *   negotiation path — take the offer, answer it, send the answer back —
 *   and video renegotiation arrives on it unchanged, because video is
 *   layered on the voice session rather than sitting beside it.
 * - **Nothing is delivered unasked.** A peer receives a publication only
 *   while it holds a subscription, so a voice-only participant is not a
 *   special case; it is a peer whose subscription set is empty.
 * - **Inbound streams are keyed by transceiver mid**, never by m-line
 *   index: sections differ per peer and move as subscriptions change.
 *   `user-{uid}` is audio, `cam-user-{uid}` and `scr-user-{uid}` video.
 *
 * Grown out of `tools/ng-voice.html`, which stays as the minimal
 * single-file rig for poking at the SFU without a build step.
 */

import type { Connection } from '../wire/connection';
import type { VideoConfig, VideoKind, VideoPublication, VoiceParticipant } from '../wire/protocol';
import { h } from './dom';

export interface MediaHooks {
  onLog: (text: string, bad?: boolean) => void;
  /** Voice membership or video publications changed: the roster shows
   *  both, so the app re-renders it. */
  onRoom: () => void;
  onControls: () => void;
  nickOf: (uid: number) => string;
}

const MID_RE = /^(cam|scr)-user-(\d+)$/;

/**
 * Why this page cannot capture a microphone or camera, or `null` when it
 * can.
 *
 * `navigator.mediaDevices` is only *defined* in a secure context. A page
 * served over plain http from anything but localhost therefore does not
 * have a `getUserMedia` that refuses politely — it has no `mediaDevices`
 * at all, and reaching through it throws a TypeError about reading a
 * property of undefined. That is exactly what a phone opening this
 * client over the LAN hits, so the condition is checked up front and
 * reported in words rather than left to surface as a type error.
 */
export function captureBlockedReason(): string | null {
  if (!window.isSecureContext) {
    return (
      `Voice needs a secure context and ${location.origin} is not one, so this ` +
      'browser withholds the microphone entirely. Serve the client over https, ' +
      'or reach it as localhost (an SSH tunnel counts).'
    );
  }
  if (!navigator.mediaDevices?.getUserMedia) {
    return 'This browser does not offer getUserMedia, so voice is unavailable here.';
  }
  return null;
}

/** Screen sharing is a separate capability, not a corollary of the one
 *  above: iOS Safari has `getUserMedia` and no `getDisplayMedia` at all. */
export function screenShareBlockedReason(): string | null {
  const blocked = captureBlockedReason();
  if (blocked) return blocked;
  // Typed as always present, actually optional in the wild.
  const md = navigator.mediaDevices as Partial<MediaDevices>;
  return md.getDisplayMedia
    ? null
    : 'This browser cannot share a screen — it has no getDisplayMedia.';
}

export class Media {
  readonly tiles: HTMLElement;

  private pc: RTCPeerConnection | null = null;
  private mic: MediaStream | null = null;
  private cam: MediaStream | null = null;
  private screen: MediaStream | null = null;
  private audioEls = new Map<string, HTMLAudioElement>();
  private tileEls = new Map<string, HTMLElement>();

  cid = 0;
  joined = false;
  muted = true;
  camPaused = false;
  watching = false;
  codec = '';
  participants: VoiceParticipant[] = [];
  publications: VideoPublication[] = [];
  limits: VideoConfig | null = null;

  constructor(
    private conn: Connection,
    private hooks: MediaHooks,
  ) {
    this.tiles = h('div', { class: 'tiles', hidden: true });

    conn.on('voice_offer', (d) => {
      void this.answerOffer(d.sdp).catch((e) => this.fail(e));
    });
    conn.on('voice_ice', (d) => {
      this.pc?.addIceCandidate(d.candidate ?? undefined).catch((e) =>
        this.hooks.onLog(`ICE candidate refused: ${e}`, true),
      );
    });
    conn.on('voice_status', (d) => {
      this.participants = d.participants;
      this.hooks.onRoom();
    });
    conn.on('video_status', (d) => {
      // The complete publication list, every time: replace the view of
      // the room rather than patching it.
      this.publications = d.publishers ?? [];
      this.pruneTiles();
      this.hooks.onRoom();
      if (this.watching) void this.subscribeAll().catch((e) => this.fail(e));
    });
  }

  get hasVoice(): boolean {
    return this.conn.caps.includes('voice');
  }

  get hasVideo(): boolean {
    return this.conn.caps.includes('video');
  }

  get publishing(): VideoKind[] {
    const out: VideoKind[] = [];
    if (this.cam) out.push('camera');
    if (this.screen) out.push('screen');
    return out;
  }

  inVoice(uid: number): VoiceParticipant | undefined {
    return this.participants.find((p) => p.uid === uid);
  }

  publicationsOf(uid: number): VideoPublication[] {
    return this.publications.filter((p) => p.uid === uid);
  }

  // --- voice ------------------------------------------------------------

  async join(): Promise<void> {
    const blocked = captureBlockedReason();
    if (blocked) throw new Error(blocked);
    this.mic = await navigator.mediaDevices.getUserMedia({ audio: true });
    this.pc = this.newPeerConnection();
    for (const t of this.mic.getTracks()) this.pc.addTrack(t, this.mic);

    const ok = await this.conn.request<{
      sdp: string;
      codec: string;
      participants: VoiceParticipant[];
    }>('voice_join', { cid: this.cid });
    this.codec = ok.codec;
    this.participants = ok.participants;
    this.joined = true;
    await this.answerOffer(ok.sdp);
    // Clients SHOULD join muted, and the server enforces it; say so
    // rather than letting the two disagree.
    await this.setMuted(true);
    this.hooks.onLog(`joined voice (${ok.codec})`);
    this.hooks.onRoom();
    this.hooks.onControls();
  }

  async leave(): Promise<void> {
    await this.conn.request('voice_leave', { cid: this.cid }).catch(() => {});
    this.teardown();
  }

  async setMuted(muted: boolean): Promise<void> {
    await this.conn.request('voice_mute', { cid: this.cid, muted });
    this.muted = muted;
    // Both sides, on purpose: replacing the microphone with silence
    // keeps RTP flowing at its normal rate, which keeps the NAT path
    // warm. Dropping the packets would save nothing worth having.
    for (const t of this.mic?.getAudioTracks() ?? []) t.enabled = !muted;
    this.hooks.onControls();
  }

  teardown(): void {
    this.pc?.close();
    this.pc = null;
    for (const t of this.mic?.getTracks() ?? []) t.stop();
    this.mic = null;
    this.stopCapture('cam');
    this.stopCapture('screen');
    for (const el of this.audioEls.values()) el.srcObject = null;
    this.audioEls.clear();
    for (const mid of [...this.tileEls.keys()]) this.dropTile(mid);
    this.joined = false;
    this.muted = true;
    this.camPaused = false;
    this.watching = false;
    this.codec = '';
    this.participants = [];
    this.publications = [];
    this.hooks.onRoom();
    this.hooks.onControls();
  }

  private newPeerConnection(): RTCPeerConnection {
    // No ICE servers: the SFU is the only peer and we already know where
    // it is. No STUN, no TURN — that is the whole point of the model.
    const pc = new RTCPeerConnection({ iceServers: [] });
    pc.onicecandidate = (e) => {
      void this.conn
        .request('voice_ice', { cid: this.cid, candidate: e.candidate ?? null })
        .catch((err: Error) => this.hooks.onLog(`voice_ice: ${err.message}`, true));
    };
    pc.ontrack = (e) => {
      const mid = e.transceiver?.mid ?? '?';
      const stream = e.streams[0] ?? new MediaStream([e.track]);
      if (e.track.kind === 'video') this.showTile(mid, stream);
      else this.playAudio(mid, stream);
    };
    pc.onconnectionstatechange = () => this.hooks.onLog(`peer connection: ${pc.connectionState}`);
    return pc;
  }

  private async answerOffer(sdp: string): Promise<void> {
    const pc = this.pc;
    if (!pc) return;
    await pc.setRemoteDescription({ type: 'offer', sdp });
    // Attach capture tracks *before* creating the answer: the answer's
    // `a=ssrc` comes from the sender's track, and the server keys
    // inbound video on it with no fallback to guess from — a camera and
    // a screen are the same codec at the same payload type on one
    // bundled transport, so there is nothing else to tell them apart.
    await this.bindSendSections();
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    await this.conn.request('voice_answer', { cid: this.cid, sdp: answer.sdp });
  }

  private async bindSendSections(): Promise<void> {
    const pc = this.pc;
    if (!pc) return;
    for (const [mid, stream] of [
      ['cam-send', this.cam],
      ['scr-send', this.screen],
    ] as const) {
      const tr = pc.getTransceivers().find((t) => t.mid === mid);
      if (!tr) continue;
      const track = stream?.getVideoTracks()[0] ?? null;
      if (tr.sender.track !== track) await tr.sender.replaceTrack(track);
      if (track) tr.direction = 'sendonly';
    }
  }

  // --- video ------------------------------------------------------------

  async toggleCamera(): Promise<void> {
    if (this.cam) {
      await this.conn.request('video_stop', { cid: this.cid, kind: 'camera' });
      this.stopCapture('cam');
      this.camPaused = false;
      this.hooks.onControls();
      return;
    }
    const blocked = captureBlockedReason();
    if (blocked) throw new Error(blocked);
    // Configure the encoder inside the advertised ceiling *before*
    // publishing: the limits are configuration, not negotiation, and a
    // client that cannot be constrained to them must not publish.
    const l = this.limits?.camera;
    this.cam = await navigator.mediaDevices.getUserMedia({
      video: {
        width: { max: l?.max_width ?? 1280 },
        height: { max: l?.max_height ?? 720 },
        frameRate: { max: l?.max_fps ?? 30 },
      },
    });
    try {
      const ok = await this.conn.request<{ codec: string }>('video_start', {
        cid: this.cid,
        kind: 'camera',
      });
      this.hooks.onLog(`publishing a camera (${ok.codec})`);
    } catch (e) {
      this.stopCapture('cam');
      throw e;
    }
    // No offer came back with that reply and none was expected: one may
    // already be outstanding toward us, and the server sends ours as a
    // voice_offer when serialisation allows.
    this.hooks.onControls();
  }

  async togglePause(): Promise<void> {
    const paused = !this.camPaused;
    await this.conn.request('video_state', { cid: this.cid, kind: 'camera', paused });
    this.camPaused = paused;
    // Pause is to video what mute is to audio: no renegotiation, the
    // section and the slot both stay. Stopping the local track as well
    // is what turns the camera's hardware light off, which is the half
    // of it people actually check.
    for (const t of this.cam?.getVideoTracks() ?? []) t.enabled = !paused;
    this.hooks.onControls();
  }

  async toggleShare(): Promise<void> {
    if (this.screen) {
      await this.conn.request('video_stop', { cid: this.cid, kind: 'screen' });
      this.stopCapture('screen');
      this.hooks.onControls();
      return;
    }
    const blocked = screenShareBlockedReason();
    if (blocked) throw new Error(blocked);
    // getDisplayMedia is its own consent step, per share, with the
    // browser's own sharing indicator — exactly what the spec asks a
    // client to provide and forbids it from remembering.
    this.screen = await navigator.mediaDevices.getDisplayMedia({
      video: {
        width: { max: this.limits?.screen.max_width ?? 1920 },
        height: { max: this.limits?.screen.max_height ?? 1080 },
        frameRate: { max: this.limits?.screen.max_fps ?? 15 },
      },
    });
    // A share can be ended from the browser's own UI, and that has to
    // reach the server or the room's one screen slot stays occupied.
    this.screen.getVideoTracks()[0]?.addEventListener('ended', () => {
      void this.toggleShare().catch((e) => this.fail(e));
    });
    try {
      await this.conn.request('video_start', { cid: this.cid, kind: 'screen' });
    } catch (e) {
      this.stopCapture('screen');
      throw e;
    }
    this.hooks.onControls();
  }

  async setWatching(on: boolean): Promise<void> {
    this.watching = on;
    if (on) await this.subscribeAll();
    else {
      // `[]` turns it all off in one request, which is the message this
      // binding exists for on a metered connection.
      await this.conn.request('video_subscribe', { cid: this.cid, streams: [] });
      for (const mid of [...this.tileEls.keys()]) this.dropTile(mid);
    }
    this.hooks.onControls();
  }

  private async subscribeAll(): Promise<void> {
    // The complete desired set in one request: four separate subscribes
    // would cost four renegotiations, serialised behind one another.
    const streams = this.publications
      .filter((p) => p.uid !== this.conn.self?.uid)
      .map((p) => ({ uid: p.uid, kind: p.kind }));
    await this.conn.request('video_subscribe', { cid: this.cid, streams });
  }

  private stopCapture(which: 'cam' | 'screen'): void {
    for (const t of this[which]?.getTracks() ?? []) t.stop();
    this[which] = null;
  }

  // --- tiles ------------------------------------------------------------

  private playAudio(mid: string, stream: MediaStream): void {
    let el = this.audioEls.get(mid);
    if (!el) {
      el = new Audio();
      el.autoplay = true;
      this.audioEls.set(mid, el);
    }
    el.srcObject = stream;
  }

  private showTile(mid: string, stream: MediaStream): void {
    let fig = this.tileEls.get(mid);
    if (!fig) {
      const video = h('video', { autoplay: true, playsInline: true, muted: true });
      fig = h('figure', { class: 'tile' }, video, h('figcaption', {}, this.tileLabel(mid)));
      this.tileEls.set(mid, fig);
      this.tiles.append(fig);
    }
    fig.querySelector('video')!.srcObject = stream;
    this.tiles.hidden = false;
  }

  private tileLabel(mid: string): string {
    const m = MID_RE.exec(mid);
    if (!m) return mid;
    const uid = Number(m[2]);
    return `${this.hooks.nickOf(uid)} — ${m[1] === 'cam' ? 'camera' : 'screen'}`;
  }

  /** Drop tiles whose publication is gone. The mid encodes uid and kind,
   *  which is exactly what `video_status` lists. */
  private pruneTiles(): void {
    for (const mid of [...this.tileEls.keys()]) {
      const m = MID_RE.exec(mid);
      if (!m) continue;
      const kind: VideoKind = m[1] === 'cam' ? 'camera' : 'screen';
      const uid = Number(m[2]);
      if (!this.publications.some((p) => p.uid === uid && p.kind === kind)) this.dropTile(mid);
    }
    for (const [mid, fig] of this.tileEls) fig.querySelector('figcaption')!.textContent = this.tileLabel(mid);
  }

  private dropTile(mid: string): void {
    this.tileEls.get(mid)?.remove();
    this.tileEls.delete(mid);
    if (this.tileEls.size === 0) this.tiles.hidden = true;
  }

  private fail(e: unknown): void {
    this.hooks.onLog(e instanceof Error ? e.message : String(e), true);
  }

  // --- for the debug drawer --------------------------------------------

  async stats(): Promise<Record<string, unknown>> {
    const facts: Record<string, unknown> = {
      'voice joined': this.joined,
      muted: this.muted,
      codec: this.codec || null,
      participants: this.participants.length,
      publications: this.publications.map((p) => `${p.uid}:${p.kind}${p.paused ? ' (paused)' : ''}`),
      publishing: this.publishing,
      watching: this.watching,
      tiles: [...this.tileEls.keys()],
      'peer connection': this.pc?.connectionState ?? null,
      'ice state': this.pc?.iceConnectionState ?? null,
      'signalling state': this.pc?.signalingState ?? null,
      mids: this.pc?.getTransceivers().map((t) => `${t.mid ?? '?'}:${t.currentDirection ?? '-'}`) ?? [],
    };
    if (!this.pc) return facts;
    try {
      const report = await this.pc.getStats();
      report.forEach((s) => {
        if (s.type === 'inbound-rtp') {
          facts[`in ${s.kind} ${s.ssrc}`] =
            `${s.packetsReceived ?? 0} pkts, ${s.packetsLost ?? 0} lost` +
            (s.framesDecoded !== undefined ? `, ${s.framesDecoded} frames` : '');
        } else if (s.type === 'outbound-rtp') {
          facts[`out ${s.kind} ${s.ssrc}`] =
            `${s.packetsSent ?? 0} pkts` +
            (s.framesEncoded !== undefined ? `, ${s.framesEncoded} frames` : '');
        } else if (s.type === 'candidate-pair' && s.state === 'succeeded') {
          facts['rtt (ice)'] = s.currentRoundTripTime !== undefined
            ? `${Math.round(s.currentRoundTripTime * 1000)} ms`
            : '—';
        }
      });
    } catch {
      /* getStats can reject on a closed connection; the facts above
         still describe the state usefully */
    }
    return facts;
  }
}
