import { useState } from 'react'

/**
 * Cover and stego image side by side, plus the amplified LSB plane.
 *
 * The spec requires the GUI to "display both cover and stego objects for
 * comparison before and after encoding and decoding". The point being made on
 * screen is that the two images look identical while their LSB planes do not.
 *
 * Everything here is plain <img>. The browser must never read pixels with
 * canvas getImageData: it premultiplies alpha and applies colour management,
 * which silently corrupts the very bits this project cares about.
 *
 * Complete — no TODO.
 */
export function ImageCompare({
  coverUrl,
  stegoUrl,
  diffUrl,
}: {
  coverUrl: string | null
  stegoUrl: string | null
  diffUrl?: string | null
}) {
  const [zoom, setZoom] = useState(false)

  const panes = [
    { label: 'Cover (original)', url: coverUrl },
    { label: 'Stego (after embedding)', url: stegoUrl },
    ...(diffUrl ? [{ label: 'LSB plane, amplified', url: diffUrl }] : []),
  ]

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <span className="font-medium">Visual comparison</span>
        <label className="flex cursor-pointer items-center gap-2 text-xs">
          <span>Pixelated zoom</span>
          <input
            type="checkbox"
            className="toggle toggle-sm"
            checked={zoom}
            onChange={(e) => setZoom(e.target.checked)}
          />
        </label>
      </div>

      <div className={`grid gap-3 ${panes.length === 3 ? 'sm:grid-cols-3' : 'sm:grid-cols-2'}`}>
        {panes.map((pane) => (
          <div key={pane.label} className="space-y-1">
            <div className="flex aspect-square items-center justify-center overflow-hidden rounded-lg border border-base-300 bg-base-200">
              {pane.url ? (
                <img
                  src={pane.url}
                  alt={pane.label}
                  className={`max-h-full max-w-full object-contain ${zoom ? 'pixelated scale-[2]' : ''}`}
                />
              ) : (
                <span className="text-xs opacity-40">not available yet</span>
              )}
            </div>
            <p className="text-center text-xs opacity-70">{pane.label}</p>
          </div>
        ))}
      </div>
    </div>
  )
}
