import type { FileRef } from '../types'
import { formatBytes } from '../lib/format'
import { Exhibit } from './Exhibit'

/**
 * Download a produced file, with its SHA-256 next to it.
 *
 * The hash chip is the point of this component during the party A to party B
 * demo: A reads the hash here before attaching the file to an email, B reads it
 * again after downloading, and the two match — proving the bytes survived the
 * trip. Send it as an ATTACHMENT. Inline images and messaging apps re-encode,
 * which wipes the LSB plane.
 *
 * Complete — no TODO.
 */
export function DownloadButton({ file, label }: { file: FileRef; label?: string }) {
  return (
    <div className="border-verdict-authentic bg-verdict-authentic/10 space-y-3 rounded-sm border p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="min-w-0">
          <div className="text-sm font-medium">{label ?? 'Stego object ready'}</div>
          <div className="font-exhibit text-xs break-all text-base-content/70">
            {file.filename} · {formatBytes(file.size_bytes)}
          </div>
        </div>
        <a href={file.download_url} download={file.filename} className="btn btn-primary btn-sm">
          Download
        </a>
      </div>

      <Exhibit label="SHA-256">{file.sha256}</Exhibit>

      <p className="text-xs text-base-content/60">
        Send this as a file attachment. Pasting it inline, or sending it through a messaging app that
        re-compresses images, destroys the hidden payload.
      </p>
    </div>
  )
}
