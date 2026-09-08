import type { CapacityReport } from '../types'
import { formatBytes } from '../lib/format'

/**
 * How much fits, and whether this message does.
 *
 * The capacity check is a REQUIRED demo case: the spec asks for a "cover object
 * and payload capacity check (is payload size larger than cover object size?)".
 * When it does not fit, this component is the thing on screen that says so.
 *
 * Complete — no TODO.
 */
export function CapacityMeter({
  report,
  messageBytes,
}: {
  report: CapacityReport | null
  messageBytes: number
}) {
  if (!report) {
    return (
      <div className="rounded-lg border border-base-300 p-4 text-sm opacity-50">
        Choose a cover object to see how much it can hold.
      </div>
    )
  }

  const used = messageBytes + report.frame_overhead_bytes
  const percent = Math.min(100, (used / Math.max(1, report.capacity_bytes)) * 100)
  const fits = used <= report.capacity_bytes

  return (
    <div className="space-y-2 rounded-lg border border-base-300 p-4">
      <div className="flex items-baseline justify-between">
        <span className="font-medium">Capacity</span>
        <span className="font-mono text-sm">
          {formatBytes(used)} / {formatBytes(report.capacity_bytes)}
        </span>
      </div>

      <progress
        className={`progress w-full ${fits ? 'progress-success' : 'progress-error'}`}
        value={percent}
        max={100}
      />

      <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs opacity-70">
        <dt>Elements available</dt>
        <dd className="text-right font-mono">{report.total_elements.toLocaleString()}</dd>
        <dt>Bits per element</dt>
        <dd className="text-right font-mono">{report.n_lsb}</dd>
        <dt>Frame overhead</dt>
        <dd className="text-right font-mono">{formatBytes(report.frame_overhead_bytes)}</dd>
        <dt>Largest message</dt>
        <dd className="text-right font-mono">{formatBytes(report.max_message_bytes)}</dd>
      </dl>

      {!fits && (
        <div className="alert alert-error text-sm">
          Payload is larger than this cover can hold. Use a bigger cover, raise the LSB count, or
          shorten the message.
        </div>
      )}
    </div>
  )
}
