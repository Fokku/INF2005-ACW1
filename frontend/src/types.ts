/**
 * Mirrors backend/app/schemas.py by hand.
 *
 * There is no code generation here on purpose: with ~10 endpoints, a hand
 * written file is easier to read than a generator pipeline. The trade is that
 * YOU must update this file when schemas.py changes. Do it in the same commit.
 */

export type CoverKind = 'image' | 'audio' | 'video'
export type StartMode = 'derived' | 'explicit'

/** The six verdict categories required by the spec (FR10). */
export type Verdict =
  | 'Authentic'
  | 'Tampered'
  | 'Signature Invalid'
  | 'Payload Missing'
  | 'Wrong Start Location'
  | 'Cannot Verify'

export type AttackKind =
  | 'flip_bits'
  | 'crop'
  | 'lsb_scrub'
  | 'reencode'
  | 'corrupt_payload'
  | 'replay'
  | 'lsb_noise'

export interface ImageInfo {
  width: number
  height: number
  channels: number
  mode: string
}

export interface AudioInfo {
  sample_rate: number
  channels: number
  sample_width_bytes: number
  frames: number
  duration_seconds: number
}

/** An AVI's PCM audio track (the carrier) plus frame size for display. */
export interface VideoInfo {
  frame_width: number
  frame_height: number
  duration_seconds: number
  sample_rate: number
  channels: number
  sample_width_bytes: number
  frames: number
}

export interface CoverInfo {
  kind: CoverKind
  filename: string
  size_bytes: number
  sha256: string
  image?: ImageInfo | null
  audio?: AudioInfo | null
  video?: VideoInfo | null
}

/** A file the backend wrote to out/ and can serve back. */
export interface FileRef {
  file_id: string
  filename: string
  mime: string
  size_bytes: number
  sha256: string
  url: string
  download_url: string
}

export interface CapacityReport {
  cover: CoverInfo
  n_lsb: number
  total_elements: number
  capacity_bits: number
  capacity_bytes: number
  /** Everything one copy loses besides the message, start_reserve_bytes included. */
  frame_overhead_bytes: number
  /** The part of frame_overhead_bytes skipped before the start offset (worst case when derived). */
  start_reserve_bytes: number
  max_message_bytes: number
  payload_bytes?: number | null
  fits?: boolean | null
  /** Copies of the frame that will be embedded (robust embedding). */
  redundancy: number
}

export interface PayloadInfo {
  version: number
  media_id: string
  timestamp: string
  cover_kind: CoverKind
  n_lsb: number
  shape: number[]
  media_hash: string
  nonce: string
  metadata: Record<string, string>
  message_mime: string
  message_encrypted: boolean
  message_decrypted: boolean
  decryption_error: string | null
  message_text?: string | null
  message_file?: FileRef | null
}

export interface ProtectResult {
  stego: FileRef
  cover: CoverInfo
  n_lsb: number
  start_mode: StartMode
  start_offset: number
  payload: PayloadInfo
  signature_b64: string
  frame_bytes: number
  capacity_bytes: number
  diff?: FileRef | null
  changed_elements?: number | null
  psnr_db?: number | null
  /** Copies of the frame that were embedded. */
  redundancy: number
  /** True when the frame was sealed (encrypted header; advanced start-location security). */
  sealed: boolean
  /** Public half of the signing key, so party A can hand it (and its fingerprint) to party B. */
  signer_public_key_pem: string
  signer_fingerprint: string
}

export interface VerifyReport {
  verdict: Verdict
  reasons: string[]
  stego: CoverInfo
  n_lsb: number
  start_mode: StartMode
  start_offset_used?: number | null
  payload_found: boolean
  signature_valid?: boolean | null
  media_hash_embedded?: string | null
  media_hash_recomputed?: string | null
  hash_match?: boolean | null
  payload?: PayloadInfo | null
  /** Copies of the frame the verifier expected. */
  redundancy: number
  /** True: a sealed frame was opened. False: a plaintext frame. Null: no frame located. */
  sealed?: boolean | null
}

export interface AttackResult {
  attack: AttackKind
  description: string
  expected_verdict: Verdict
  output: FileRef
}

export interface AttackKindInfo {
  kind: AttackKind
  expected_verdict: Verdict
  description: string
}

export interface KeyInfo {
  key_id: string
  label: string
  algorithm: string
  public_key_pem: string
  fingerprint: string
  created_at?: string | null
}

export interface KeyPairResult {
  key: KeyInfo
  public_key_file: FileRef
  private_key_file: FileRef
}

export interface HealthResponse {
  status: string
  version: string
  frontend_built: boolean
}

/** Shape of an error body from the API. */
export interface ApiErrorBody {
  error: string
  detail?: string | null
  /** Present on 501s: names the backend function a teammate still has to write. */
  todo?: string | null
}

/** A curated file under samples/ with the exact settings that reproduce its verdict. */
export interface SampleCase {
  id: string
  label: string
  kind: CoverKind
  file: string
  url: string
  expected_verdict: Verdict
  media_id: string
  n_lsb: number
  start_mode: StartMode
  explicit_start: number | null
  passphrase: string | null
  /** A file name under keys/public/. */
  public_key: string
  redundancy: number
  note: string | null
}

/** A committed public key under keys/public/. */
export interface PublicKeyFile {
  name: string
  fingerprint: string
  public_key_pem: string
  url: string
}

/** One window of the per-region steganalysis scan. */
export interface SteganalysisWindow {
  start: number
  end: number
  chi_square_p: number | null
  phase_p: number | null
  flagged: boolean
}

/** Chi-square (pairs of values) + byte-phase steganalysis of one file. */
export interface SteganalysisReport {
  filename: string
  kind: CoverKind
  elements: number
  window: number
  chi_square_p: number | null
  phase_p: number | null
  phase_n_lsb_guess: number | null
  suspicious: boolean
  verdict: string
  summary: string
  suspected_region: { start: number; end: number } | null
  windows: SteganalysisWindow[]
  /** Counts at full resolution; `windows` may merge neighbours for the chart. */
  windows_total: number
  windows_flagged: number
  /** How many analysis windows each entry of `windows` covers (1 = none merged). */
  windows_merged: number
  method: string
}

/**
 * Settings handed to the Verify tab from elsewhere in the app: the Protect
 * tab's hand-off, an Attack Lab output, or a curated sample. `id` changes on
 * every hand-off so the same settings can be re-applied.
 */
export interface VerifyPrefill {
  id: number
  source: string
  file: File
  mediaId: string
  nLsb: number
  redundancy: number
  startMode: StartMode
  explicitStart?: number | null
  passphrase?: string | null
  publicKeyPem?: string | null
  publicKeyLabel?: string | null
  expectedSha256?: string | null
  expectedVerdict?: Verdict | null
  note?: string | null
  /**
   * The file cannot be checked without the shared passphrase, even in explicit
   * start mode: its frame is sealed, and a sealed frame is invisible without
   * the key derived from it. Verify then blocks until a passphrase is typed,
   * and keeps one already typed when the prefill carries none.
   */
  requiresPassphrase?: boolean
}

/** What the Protect tab produced last, shared with Verify and the Attack Lab. */
export interface ProtectHandoff {
  result: ProtectResult
  mediaId: string
  startMode: StartMode
}

/** A protected file handed to the Attack Lab, with the settings it was embedded with. */
export interface AttackPrefill {
  id: number
  source: string
  file: File
  nLsb: number
  startOffset: number
  mediaId: string
  redundancy: number
  /** The target holds a sealed frame (the Attack Lab then uses key-less variants). */
  sealed?: boolean
  /** The hidden message was encrypted (Verify needs the passphrase to show it). */
  messageEncrypted?: boolean
  publicKeyPem?: string | null
  publicKeyLabel?: string | null
}
