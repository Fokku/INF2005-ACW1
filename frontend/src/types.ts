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
  frame_overhead_bytes: number
  max_message_bytes: number
  payload_bytes?: number | null
  fits?: boolean | null
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
