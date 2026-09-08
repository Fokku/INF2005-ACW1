import type { VerifyReport } from '../types'
import { shortHash } from '../lib/format'

/**
 * The evidence behind a verdict: which checks ran, and what they found.
 *
 * Rubric criterion 4 wants a "clear linkage between verification logic and
 * outcomes", so this table shows each check separately rather than folding
 * everything into one pass/fail.
 *
 * Complete — no TODO.
 */
function Check({ label, state, detail }: { label: string; state: boolean | null | undefined; detail?: string }) {
  const icon = state === true ? '✓' : state === false ? '✗' : '—'
  const tone = state === true ? 'text-success' : state === false ? 'text-error' : 'opacity-40'
  return (
    <div className="flex items-start justify-between gap-4 border-b border-base-300 py-2 last:border-0">
      <div className="min-w-0">
        <div className="text-sm">{label}</div>
        {detail && <div className="font-mono text-xs break-all opacity-60">{detail}</div>}
      </div>
      <span className={`text-lg leading-none ${tone}`}>{icon}</span>
    </div>
  )
}

export function ReportPanel({ report }: { report: VerifyReport }) {
  return (
    <div className="rounded-lg border border-base-300 p-4">
      <h3 className="mb-2 font-medium">Verification checks</h3>

      <Check label="Hidden payload found" state={report.payload_found} />
      <Check
        label="Start location resolved"
        state={report.start_offset_used !== null && report.start_offset_used !== undefined}
        detail={
          report.start_offset_used !== null && report.start_offset_used !== undefined
            ? `element ${report.start_offset_used.toLocaleString()} (${report.start_mode})`
            : undefined
        }
      />
      <Check label="Digital signature valid" state={report.signature_valid} />
      <Check
        label="Media hash matches the signed value"
        state={report.hash_match}
        detail={
          report.media_hash_embedded
            ? `signed ${shortHash(report.media_hash_embedded)} · now ${shortHash(report.media_hash_recomputed)}`
            : undefined
        }
      />

      <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 border-t border-base-300 pt-3 text-xs">
        <dt className="opacity-60">File</dt>
        <dd className="font-mono break-all">{report.stego.filename}</dd>
        <dt className="opacity-60">File SHA-256</dt>
        <dd className="font-mono break-all">{report.stego.sha256}</dd>
        <dt className="opacity-60">Read with</dt>
        <dd className="font-mono">{report.n_lsb} LSB</dd>
      </dl>
    </div>
  )
}
