import type { CapacityReport } from '../types'
import { formatBytes } from '../lib/format'
import { Exhibit } from './Exhibit'

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
      <div className="border-base-300 text-base-content/50 border border-dashed p-4 text-sm">
        Choose a cover object to see how much it can hold.
      </div>
    )
  }

  const used = messageBytes + report.frame_overhead_bytes
  const percent = Math.min(100, (used / Math.max(1, report.capacity_bytes)) * 100)
  const fits = used <= report.capacity_bytes

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-4">
        <progress
          className={`progress flex-1 ${fits ? 'progress-primary' : 'progress-error'}`}
          value={percent}
          max={100}
        />
        <Exhibit label="Used / capacity">
          {formatBytes(used)} / {formatBytes(report.capacity_bytes)}
        </Exhibit>
      </div>

      <dl className="text-base-content/70 grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
        <dt>Elements available</dt>
        <dd className="font-exhibit text-right">{report.total_elements.toLocaleString()}</dd>
        <dt>Bits per element</dt>
        <dd className="font-exhibit text-right">{report.n_lsb}</dd>
        <dt>Frame overhead</dt>
        <dd className="font-exhibit text-right">{formatBytes(report.frame_overhead_bytes)}</dd>
        <dt>Largest message</dt>
        <dd className="font-exhibit text-right">{formatBytes(report.max_message_bytes)}</dd>
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
