import type { PayloadInfo } from '../types'
import { Exhibit } from './Exhibit'

/**
 * The extracted hidden message, displayed or PLAYED according to its type.
 *
 * This is what satisfies the spec's requirement that the GUI can
 * "play(execute) payload". A text payload is shown, an image payload is shown,
 * an audio payload gets a player, and anything else is offered as a download.
 *
 * Complete — no TODO.
 */
export function PayloadPreview({ payload }: { payload: PayloadInfo }) {
  const file = payload.message_file
  const mime = payload.message_mime

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="font-stamp text-lg">Extracted payload</h3>
        <span className="font-exhibit text-xs text-base-content/60">{mime}</span>
        {payload.message_encrypted && (
          <span className="badge badge-primary badge-sm">decrypted with AES-256-GCM</span>
        )}
      </div>

      {payload.message_text !== null && payload.message_text !== undefined ? (
        <pre className="border-base-300 bg-base-200 max-h-64 overflow-auto rounded-sm border p-3 text-sm whitespace-pre-wrap">
          {payload.message_text}
        </pre>
      ) : file && mime.startsWith('image/') ? (
        <img src={file.url} alt="extracted payload" className="border-base-300 max-h-64 rounded-sm border" />
      ) : file && mime.startsWith('audio/') ? (
        <audio controls src={file.url} className="w-full" />
      ) : file ? (
        <a href={file.download_url} className="btn btn-outline btn-sm">
          Download {file.filename}
        </a>
      ) : (
        <p className="text-sm text-base-content/50">No message content returned.</p>
      )}

      <div className="grid gap-3 sm:grid-cols-2">
        <Exhibit label="Media ID">{payload.media_id}</Exhibit>
        <Exhibit label="Signed at">{payload.timestamp}</Exhibit>
        <Exhibit label="Nonce">{payload.nonce}</Exhibit>
        <Exhibit label="Media hash">{payload.media_hash}</Exhibit>
        <Exhibit label="Bound parameters">
          {payload.cover_kind}, {payload.n_lsb} LSB, shape [{payload.shape.join(', ')}]
        </Exhibit>
        {Object.entries(payload.metadata).map(([key, value]) => (
          <Exhibit key={key} label={key}>
            {value}
          </Exhibit>
        ))}
      </div>
    </div>
  )
}
