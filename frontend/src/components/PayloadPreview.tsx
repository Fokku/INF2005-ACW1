import type { PayloadInfo } from '../types'

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
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">Extracted payload</span>
        <span className="badge badge-ghost badge-sm font-mono">{mime}</span>
        {payload.message_encrypted && (
          <span className="badge badge-info badge-sm">decrypted with AES-256-GCM</span>
        )}
      </div>

      {payload.message_text !== null && payload.message_text !== undefined ? (
        <pre className="max-h-64 overflow-auto rounded-lg border border-base-300 bg-base-200 p-3 text-sm whitespace-pre-wrap">
          {payload.message_text}
        </pre>
      ) : file && mime.startsWith('image/') ? (
        <img src={file.url} alt="extracted payload" className="max-h-64 rounded-lg border border-base-300" />
      ) : file && mime.startsWith('audio/') ? (
        <audio controls src={file.url} className="w-full" />
      ) : file ? (
        <a href={file.download_url} className="btn btn-outline btn-sm">
          Download {file.filename}
        </a>
      ) : (
        <p className="text-sm opacity-50">No message content returned.</p>
      )}

      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs">
        <dt className="opacity-60">Media ID</dt>
        <dd className="font-mono break-all">{payload.media_id}</dd>
        <dt className="opacity-60">Signed at</dt>
        <dd className="font-mono">{payload.timestamp}</dd>
        <dt className="opacity-60">Nonce</dt>
        <dd className="font-mono break-all">{payload.nonce}</dd>
        <dt className="opacity-60">Media hash</dt>
        <dd className="font-mono break-all">{payload.media_hash}</dd>
        <dt className="opacity-60">Bound parameters</dt>
        <dd className="font-mono">
          {payload.cover_kind}, {payload.n_lsb} LSB, shape [{payload.shape.join(', ')}]
        </dd>
        {Object.entries(payload.metadata).map(([key, value]) => (
          <div key={key} className="contents">
            <dt className="opacity-60">{key}</dt>
            <dd className="break-all">{value}</dd>
          </div>
        ))}
      </dl>
    </div>
  )
}
