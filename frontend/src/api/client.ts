/**
 * Thin fetch wrapper around the FastAPI backend.
 *
 * This file is COMPLETE. Every function already sends the right request; they
 * return 501 today only because the backend core is unimplemented. When a
 * teammate fills in a stego_core function, the matching screen starts working
 * with no change here.
 */

import type {
  ApiErrorBody,
  AttackKind,
  AttackKindInfo,
  AttackResult,
  CapacityReport,
  HealthResponse,
  KeyInfo,
  KeyPairResult,
  ProtectResult,
  StartMode,
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

  capacity: (args: { cover: File; nLsb: number; payloadBytes?: number }) =>
    request<CapacityReport>('/api/capacity', {
      method: 'POST',
      body: form({ cover: args.cover, n_lsb: args.nLsb, payload_bytes: args.payloadBytes }),
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
      }),
    }),

  attackKinds: () => request<AttackKindInfo[]>('/api/attack/kinds'),

  runAttack: (args: {
    stego: File
    attack: AttackKind
    nLsb: number
    startOffset: number
    otherCover?: File
  }) =>
    request<AttackResult>('/api/attack', {
      method: 'POST',
      body: form({
        stego: args.stego,
        attack: args.attack,
        n_lsb: args.nLsb,
        start_offset: args.startOffset,
        other_cover: args.otherCover,
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
}
