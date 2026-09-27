import { useState } from 'react'
import { formatP } from '../lib/format'
import type { SteganalysisWindow } from '../types'

/**
 * Per-window steganalysis evidence along the file: one column per window,
 * height = −log10(byte-phase p), so "more certain something is hidden here"
 * reads as "taller". Columns past the detection threshold are drawn in the
 * warning hue and labelled "flagged" in the tooltip and the table below, so
 * the state never depends on colour alone.
 *
 * Display only: all numbers come from POST /api/steganalysis.
 */

const HEIGHT = 180
const PAD = { top: 12, right: 8, bottom: 24, left: 36 }
/** Evidence is capped for display; the tooltip and table keep the true p. */
const CAP = 20

function evidence(p: number | null): number {
  if (p === null || p <= 0) return p === 0 ? CAP : 0
  return Math.min(CAP, -Math.log10(p))
}

export function EvidenceStrip({
  windows,
  threshold,
  elements,
}: {
  windows: SteganalysisWindow[]
  threshold: number
  elements: number
}) {
  const [hover, setHover] = useState<number | null>(null)
  const width = 640
  const plotW = width - PAD.left - PAD.right
  const plotH = HEIGHT - PAD.top - PAD.bottom
  const slot = plotW / Math.max(1, windows.length)
  // Bars never fill the slot: cap at 24px and leave a 2px surface gap when there is room.
  const barW = Math.max(1, Math.min(24, slot - (slot > 4 ? 2 : 0)))
  const y = (v: number) => PAD.top + plotH - (v / CAP) * plotH
  const thresholdY = y(-Math.log10(threshold))
  const ticks = [0, 5, 10, 15, 20]
  const hovered = hover !== null ? windows[hover] : null

  return (
    <div className="relative">
      <svg
        viewBox={`0 0 ${width} ${HEIGHT}`}
        className="w-full"
        role="img"
        aria-label={`Byte-phase evidence for ${windows.length} windows; ${windows.filter((w) => w.flagged).length} flagged`}
        onPointerLeave={() => setHover(null)}
      >
        {ticks.map((t) => (
          <g key={t}>
            <line
              x1={PAD.left}
              x2={width - PAD.right}
              y1={y(t)}
              y2={y(t)}
              className="stroke-base-300"
              strokeWidth={1}
            />
            <text x={PAD.left - 6} y={y(t) + 3} textAnchor="end" className="fill-base-content/50 text-[10px]">
              {t === CAP ? `≥${t}` : t}
            </text>
          </g>
        ))}

        {windows.map((w, i) => {
          const v = evidence(w.phase_p)
          const x = PAD.left + i * slot + (slot - barW) / 2
          const top = y(v)
          const h = PAD.top + plotH - top
          const r = Math.min(4, barW / 2, h)
          return (
            <g key={w.start}>
              {h > 0 && (
                <path
                  // Rounded data-end, square at the baseline.
                  d={`M${x},${top + h} V${top + r} Q${x},${top} ${x + r},${top} H${x + barW - r} Q${x + barW},${top} ${x + barW},${top + r} V${top + h} Z`}
                  className={w.flagged ? 'fill-warning' : 'fill-base-content/35'}
                  opacity={hover === null || hover === i ? 1 : 0.55}
                />
              )}
              {/* The hit target is the whole slot, taller and wider than the bar. */}
              <rect
                x={PAD.left + i * slot}
                y={PAD.top}
                width={slot}
                height={plotH}
                fill="transparent"
                tabIndex={0}
                aria-label={`elements ${w.start}–${w.end}, byte-phase p ${formatP(w.phase_p)}${w.flagged ? ', flagged' : ''}`}
                onPointerMove={() => setHover(i)}
                onFocus={() => setHover(i)}
                onBlur={() => setHover(null)}
              />
            </g>
          )
        })}

        <line
          x1={PAD.left}
          x2={width - PAD.right}
          y1={thresholdY}
          y2={thresholdY}
          className="stroke-base-content/70"
          strokeWidth={1}
        />
        <text x={width - PAD.right} y={thresholdY - 4} textAnchor="end" className="fill-base-content/70 text-[10px]">
          threshold p = {threshold.toExponential(0)}
        </text>

        <text x={PAD.left} y={HEIGHT - 6} className="fill-base-content/50 text-[10px]">
          element 0
        </text>
        <text x={width - PAD.right} y={HEIGHT - 6} textAnchor="end" className="fill-base-content/50 text-[10px]">
          {elements.toLocaleString()}
        </text>
      </svg>

      {hovered && hover !== null && (
        <div
          className="border-base-300 bg-base-200 pointer-events-none absolute top-0 z-10 rounded-sm border px-3 py-2 text-xs shadow"
          style={{
            left: `${Math.min(70, Math.max(0, ((PAD.left + hover * slot) / width) * 100 - 10))}%`,
          }}
        >
          <div className="font-exhibit text-sm font-medium">p = {formatP(hovered.phase_p)}</div>
          <div className="text-base-content/70">
            elements {hovered.start.toLocaleString()}–{hovered.end.toLocaleString()}
          </div>
          <div className="text-base-content/70">chi-square p = {formatP(hovered.chi_square_p)}</div>
          <div className={hovered.flagged ? 'text-warning font-medium' : 'text-base-content/60'}>
            {hovered.flagged ? '▲ flagged' : 'below threshold'}
          </div>
        </div>
      )}

      <p className="mt-1 text-xs text-base-content/60">
        Height: evidence of hidden bytes, −log₁₀(byte-phase p), capped at {CAP}. Amber columns are
        flagged (p below the threshold line).
      </p>
    </div>
  )
}
