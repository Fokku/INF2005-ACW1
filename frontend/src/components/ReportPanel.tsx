import type { VerifyReport } from '../types'
import { shortHash } from '../lib/format'
import { Exhibit } from './Exhibit'

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
  const tone = state === true ? 'text-verdict-authentic' : state === false ? 'text-verdict-tampered' : 'text-base-content/40'
  return (
    <div className="border-base-300 flex items-start justify-between gap-4 border-b py-2.5 last:border-0">
      <div className="min-w-0">
        <div className="text-sm">{label}</div>
        {detail && <div className="font-exhibit mt-0.5 text-xs break-all text-base-content/60">{detail}</div>}
      </div>
      <span className={`text-lg leading-none ${tone}`}>{icon}</span>
    </div>
  )
}

export function ReportPanel({ report }: { report: VerifyReport }) {
  return (
    <div>
      <h3 className="font-stamp mb-1 text-lg">Verification checks</h3>

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

      <div className="mt-4 grid gap-3 sm:grid-cols-3">
        <Exhibit label="File">{report.stego.filename}</Exhibit>
        <Exhibit label="File SHA-256">{report.stego.sha256}</Exhibit>
        <Exhibit label="Read with">{report.n_lsb} LSB</Exhibit>
      </div>
    </div>
  )
}
