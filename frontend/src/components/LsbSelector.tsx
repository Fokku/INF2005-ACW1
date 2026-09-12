/**
 * Number of least-significant bits to use, 1 to 8.
 *
 * Required by the spec: "selectable LSBs from bits 1 to 8 of the cover object.
 * Selection of number of LSBs to be implemented as part of GUI."
 *
 * Complete — no TODO. The quality note under the slider is what makes the
 * trade-off obvious during the demo: more bits means more capacity and more
 * visible or audible distortion.
 */

const QUALITY: Record<number, { text: string; tone: string }> = {
  1: { text: 'Invisible / inaudible. Smallest capacity.', tone: 'text-success' },
  2: { text: 'Still imperceptible in most covers.', tone: 'text-success' },
  3: { text: 'Slight noise in flat areas.', tone: 'text-success' },
  4: { text: 'Visible banding on gradients; audible hiss on quiet audio.', tone: 'text-warning' },
  5: { text: 'Noticeable distortion.', tone: 'text-warning' },
  6: { text: 'Clearly degraded.', tone: 'text-warning' },
  7: { text: 'Severe distortion.', tone: 'text-error' },
  8: { text: 'Replaces the whole low byte — the cover is destroyed.', tone: 'text-error' },
}

export function LsbSelector({
  value,
  onChange,
  disabled,
}: {
  value: number
  onChange: (value: number) => void
  disabled?: boolean
}) {
  const quality = QUALITY[value]
  return (
    <div className="w-full">
      <div className="flex items-center gap-4">
        <div className="flex-1">
          <label htmlFor="lsb-range" className="text-sm font-medium text-base-content/80">
            Least-significant bits
          </label>

          <input
            id="lsb-range"
            type="range"
            min={1}
            max={8}
            step={1}
            value={value}
            disabled={disabled}
            onChange={(e) => onChange(Number(e.target.value))}
            className="range range-primary range-sm mt-2 w-full"
          />

          <div className="mt-1 flex justify-between px-1 text-xs text-base-content/40">
            {[1, 2, 3, 4, 5, 6, 7, 8].map((n) => (
              <span key={n}>{n}</span>
            ))}
          </div>
        </div>

        <span className="font-stamp text-primary w-10 shrink-0 text-center text-4xl leading-none">
          {value}
        </span>
      </div>

      <p className={`mt-2 text-xs ${quality.tone}`}>{quality.text}</p>
    </div>
  )
}
