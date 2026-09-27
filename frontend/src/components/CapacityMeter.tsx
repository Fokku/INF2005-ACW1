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
  error,
}: {
  report: CapacityReport | null
  messageBytes: number
  /** Why the last capacity check failed (e.g. metadata that is not a JSON object). */
  error?: string | null
}) {
  if (!report) {
    return (
      <div className="border-base-300 text-base-content/50 border border-dashed p-4 text-sm">
        {error ? `Capacity check failed: ${error}` : 'Choose a cover object to see how much it can hold.'}
      </div>
    )
  }

  // Robust embedding writes the whole frame `redundancy` times.
  const used = (messageBytes + report.frame_overhead_bytes) * report.redundancy
  const percent = Math.min(100, (used / Math.max(1, report.capacity_bytes)) * 100)
  // The backend's answer also counts the start offset (a derived start is
  // assumed to land as late as it can) and the encryption overhead, so it is
  // what Protect will actually do. Until a report for this exact message size
  // arrives (the check waits for typing to pause), compare with the largest
  // message instead, which is exact for the same settings.
  const fits =
    report.payload_bytes === messageBytes && report.fits != null
      ? report.fits
      : messageBytes <= report.max_message_bytes
  // Everything fits in the cover as a whole, but not after the start offset.
  const startTooLate = !fits && used <= report.capacity_bytes

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
        <dd className="font-exhibit text-right">
          {formatBytes(report.frame_overhead_bytes - report.start_reserve_bytes)}
        </dd>
        <dt title="Room before the start offset cannot hold the frame. For a derived start this is the worst case.">
          Before the start offset
        </dt>
        <dd className="font-exhibit text-right">{formatBytes(report.start_reserve_bytes)}</dd>
        <dt>Copies embedded</dt>
        <dd className="font-exhibit text-right">{report.redundancy}</dd>
        <dt>Largest message</dt>
        <dd className="font-exhibit text-right">{formatBytes(report.max_message_bytes)}</dd>
      </dl>

      {!fits && (
        <div className="alert alert-error text-sm">
          Payload is larger than this cover can hold.{' '}
          {startTooLate && 'Every copy of the frame has to fit after the start offset, which leaves less room. '}
          Use a bigger cover, raise the LSB count, embed fewer copies, or shorten the message.
        </div>
      )}
    </div>
  )
}
