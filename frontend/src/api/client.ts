/**
 * Thin fetch wrapper around the FastAPI backend. One function per endpoint;
 * multipart form fields use the backend's snake_case names.
 */

import type {
  ApiErrorBody,
  AttackKind,
  AttackKindInfo,
  AttackResult,
  CapacityReport,
  FileRef,
  HealthResponse,
  KeyInfo,
  KeyPairResult,
  ProtectResult,
  PublicKeyFile,
  SampleCase,
  StartMode,
  SteganalysisReport,
  VerifyReport,
} from '../types'

/** An API call that failed, carrying the backend's structured reason. */
export class ApiError extends Error {
  readonly status: number
  readonly body: ApiErrorBody

  constructor(status: number, body: ApiErrorBody) {
    super(body.detail || body.error || `Request failed with status ${status}`)
    this.name = 'ApiError'
    this.status = status
    this.body = body
  }

  /** True when the backend feature simply has not been written yet. */
  get isNotImplemented(): boolean {
    return this.status === 501 || this.body.error === 'not_implemented'
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, init)
  if (!response.ok) {
    let body: ApiErrorBody = { error: 'http_error', detail: response.statusText }
    try {
      body = (await response.json()) as ApiErrorBody
    } catch {
      // Response was not JSON; keep the fallback above.
    }
    throw new ApiError(response.status, body)
  }
  return (await response.json()) as T
}

/** Build multipart form data, skipping empty values. */
function form(fields: Record<string, string | number | boolean | File | null | undefined>): FormData {
  const data = new FormData()
  for (const [key, value] of Object.entries(fields)) {
    if (value === null || value === undefined || value === '') continue
    data.append(key, value instanceof File ? value : String(value))
  }
  return data
}

export const api = {
  health: () => request<HealthResponse>('/api/health'),

  /**
   * The media ID, metadata, encryption flag and start settings are optional
   * but make the answer exact: they all change how many bytes the frame needs
   * and where it may begin, so with them `fits` agrees with what Protect will do.
   */
  capacity: (args: {
    cover: File
    nLsb: number
    payloadBytes?: number
    redundancy: number
    sealFrame?: boolean
    mediaId?: string
    metadataJson?: string
    encryptMessage?: boolean
    startMode?: StartMode
    /** Sent only in explicit mode; a derived start is sized for the worst case. */
    explicitStart?: number
  }) =>
    request<CapacityReport>('/api/capacity', {
      method: 'POST',
      body: form({
        cover: args.cover,
        n_lsb: args.nLsb,
        payload_bytes: args.payloadBytes,
        redundancy: args.redundancy,
        seal_frame: args.sealFrame,
        media_id: args.mediaId,
        metadata_json: args.metadataJson,
        encrypt_message: args.encryptMessage,
        start_mode: args.startMode,
        explicit_start: args.startMode === 'explicit' ? args.explicitStart : undefined,
      }),
    }),

  protect: (args: {
    cover: File
    messageText?: string
    messageFile?: File
    messageMime: string
    nLsb: number
    mediaId: string
    metadataJson: string
    startMode: StartMode
    explicitStart?: number
    passphrase?: string
    encryptMessage: boolean
    privateKeyPem?: File
    redundancy: number
    sealFrame: boolean
  }) =>
    request<ProtectResult>('/api/protect', {
      method: 'POST',
      body: form({
        cover: args.cover,
        message: args.messageFile,
        message_text: args.messageText,
        message_mime: args.messageMime,
        n_lsb: args.nLsb,
        media_id: args.mediaId,
        metadata_json: args.metadataJson,
        start_mode: args.startMode,
        explicit_start: args.explicitStart,
        passphrase: args.passphrase,
        encrypt_message: args.encryptMessage,
        private_key_pem: args.privateKeyPem,
        redundancy: args.redundancy,
        seal_frame: args.sealFrame,
      }),
    }),

  verify: (args: {
    stego: File
    publicKeyFile?: File
    publicKeyText?: string
    nLsb: number
    mediaId: string
    startMode: StartMode
    explicitStart?: number
    passphrase?: string
    redundancy: number
  }) =>
    request<VerifyReport>('/api/verify', {
      method: 'POST',
      body: form({
        stego: args.stego,
        public_key_pem: args.publicKeyFile,
        public_key_text: args.publicKeyText,
        n_lsb: args.nLsb,
        media_id: args.mediaId,
        start_mode: args.startMode,
        explicit_start: args.explicitStart,
        passphrase: args.passphrase,
        redundancy: args.redundancy,
      }),
    }),

  attackKinds: () => request<AttackKindInfo[]>('/api/attack/kinds'),

  runAttack: (args: {
    stego: File
    attack: AttackKind
    nLsb: number
    startOffset: number
    otherCover?: File
    sealed?: boolean
    /** Copies of the frame in the target: corrupt_payload and replay must damage or move all of them. */
    redundancy: number
  }) =>
    request<AttackResult>('/api/attack', {
      method: 'POST',
      body: form({
        stego: args.stego,
        attack: args.attack,
        n_lsb: args.nLsb,
        start_offset: args.startOffset,
        other_cover: args.otherCover,
        sealed: args.sealed,
        redundancy: args.redundancy,
      }),
    }),

  generateKeys: (label: string) =>
    request<KeyPairResult>(`/api/keys/generate?label=${encodeURIComponent(label)}`, {
      method: 'POST',
    }),

  inspectKey: (publicKeyPem: string) =>
    request<KeyInfo>('/api/keys/inspect', {
      method: 'POST',
      body: form({ public_key_pem: publicKeyPem }),
    }),

  publicKeys: () => request<PublicKeyFile[]>('/api/keys/public'),

  samples: () => request<SampleCase[]>('/api/samples'),

  /** An AVI's PCM audio track as a WAV the browser can play (display only). */
  audioTrack: (file: File) =>
    request<FileRef>('/api/preview/audio-track', { method: 'POST', body: form({ file }) }),

  steganalysis: (args: { file: File; window: number }) =>
    request<SteganalysisReport>('/api/steganalysis', {
      method: 'POST',
      body: form({ file: args.file, window: args.window }),
    }),
}

/**
 * Fetch a file the backend serves (a stego output, an attack output, a sample)
 * as a File, so it can be handed to another tab exactly as if it had been
 * picked from disk. Bytes are copied untouched — no canvas, no decoding.
 */
export async function fetchAsFile(url: string, filename: string, mime?: string): Promise<File> {
  const response = await fetch(url)
  if (!response.ok) throw new ApiError(response.status, { error: 'http_error', detail: response.statusText })
  const blob = await response.blob()
  return new File([blob], filename, { type: mime ?? blob.type })
}
