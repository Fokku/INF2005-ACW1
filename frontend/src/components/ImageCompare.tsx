import { useEffect, useRef, useState } from 'react'

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
const MIN_ZOOM = 1
const MAX_ZOOM = 8
const ZOOM_STEP = 0.5

function clampZoom(value: number) {
  return Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, value))
}

export function ImageCompare({
  coverUrl,
  stegoUrl,
  diffUrl,
}: {
  coverUrl: string | null
  stegoUrl: string | null
  diffUrl?: string | null
}) {
  const [zoomLevel, setZoomLevel] = useState(1)
  const zoom = zoomLevel > MIN_ZOOM

  const panes = [
    { label: 'Cover (original)', url: coverUrl },
    { label: 'Stego (after embedding)', url: stegoUrl },
    ...(diffUrl ? [{ label: 'LSB plane, amplified', url: diffUrl }] : []),
  ]

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="font-stamp text-lg">Visual comparison</h3>
        <span className="text-xs text-base-content/70">
          {zoom
            ? `${zoomLevel.toFixed(zoomLevel % 1 === 0 ? 0 : 1)}x — scroll or +/- to zoom, drag or arrow keys to pan`
            : 'Hover an image and scroll (or press +) to zoom in'}
        </span>
      </div>

      <div className="space-y-4">
        {panes.map((pane) => (
          // Keying on the pane's identity (not the zoom level) remounts it
          // only when the image itself changes, so continuous mouse-wheel
          // zooming doesn't reset the pan offset on every tick.
          <ZoomPane
            key={`${pane.label}-${pane.url ?? ''}`}
            label={pane.label}
            url={pane.url}
            zoomLevel={zoomLevel}
            onZoomChange={setZoomLevel}
          />
        ))}
      </div>
    </div>
  )
}

const KEY_PAN_STEP = 20 // px per arrow-key press
const KEY_PAN_STEP_FAST = 80 // px per arrow-key press while holding Shift

/** One image pane. Above 1x the image is scaled with nearest-neighbour
 * rendering and can be panned — by dragging, or (for keyboard users) with the
 * arrow keys once the image is focused — since scaling alone would just clip
 * the edges against the frame that clips overflow. Zoom itself is driven by
 * the mouse wheel or the +/- keys, shared across every pane so cover and
 * stego stay at the same magnification for a fair comparison. */
function ZoomPane({
  label,
  url,
  zoomLevel,
  onZoomChange,
}: {
  label: string
  url: string | null
  zoomLevel: number
  onZoomChange: (updater: (prev: number) => number) => void
}) {
  const zoom = zoomLevel > MIN_ZOOM
  const [offset, setOffset] = useState({ x: 0, y: 0 })
  const dragRef = useRef<{ startX: number; startY: number; origin: { x: number; y: number } } | null>(
    null,
  )
  const imgRef = useRef<HTMLImageElement | null>(null)

  // React's onWheel is passive, so it cannot stop the page from scrolling
  // underneath the image. A native listener registered with passive: false
  // can, so wheel-to-zoom is wired up here instead of as a JSX prop.
  useEffect(() => {
    const el = imgRef.current
    if (!el) return
    function handleWheel(e: WheelEvent) {
      e.preventDefault()
      const next = clampZoom(zoomLevel + (e.deltaY < 0 ? ZOOM_STEP : -ZOOM_STEP))
      if (next === MIN_ZOOM) setOffset({ x: 0, y: 0 })
      onZoomChange(() => next)
    }
    el.addEventListener('wheel', handleWheel, { passive: false })
    return () => el.removeEventListener('wheel', handleWheel)
  }, [zoomLevel, onZoomChange])

  function onPointerDown(e: React.PointerEvent<HTMLImageElement>) {
    if (!zoom) return
    e.currentTarget.setPointerCapture(e.pointerId)
    dragRef.current = { startX: e.clientX, startY: e.clientY, origin: offset }
  }

  function onPointerMove(e: React.PointerEvent<HTMLImageElement>) {
    if (!zoom || !dragRef.current) return
    const { startX, startY, origin } = dragRef.current
    setOffset({ x: origin.x + (e.clientX - startX), y: origin.y + (e.clientY - startY) })
  }

  function onPointerUp(e: React.PointerEvent<HTMLImageElement>) {
    if (e.currentTarget.hasPointerCapture(e.pointerId)) {
      e.currentTarget.releasePointerCapture(e.pointerId)
    }
    dragRef.current = null
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLImageElement>) {
    if (e.key === '+' || e.key === '=' || e.key === '-' || e.key === '_') {
      e.preventDefault()
      const next = clampZoom(zoomLevel + (e.key === '-' || e.key === '_' ? -ZOOM_STEP : ZOOM_STEP))
      if (next === MIN_ZOOM) setOffset({ x: 0, y: 0 })
      onZoomChange(() => next)
      return
    }

    if (!zoom) return
    const step = e.shiftKey ? KEY_PAN_STEP_FAST : KEY_PAN_STEP
    const deltas: Record<string, [number, number]> = {
      ArrowLeft: [step, 0],
      ArrowRight: [-step, 0],
      ArrowUp: [0, step],
      ArrowDown: [0, -step],
    }
    const delta = deltas[e.key]
    if (!delta) return
    e.preventDefault()
    setOffset((prev) => ({ x: prev.x + delta[0], y: prev.y + delta[1] }))
  }

  return (
    <div className="space-y-1">
      <p className="text-xs text-base-content/70">{label}</p>
      <div className="border-base-300 bg-base-200 flex max-h-[28rem] min-h-56 items-center justify-center overflow-hidden rounded-sm border">
        {url ? (
          <img
            ref={imgRef}
            src={url}
            alt={label}
            draggable={false}
            tabIndex={0}
            onPointerDown={onPointerDown}
            onPointerMove={onPointerMove}
            onPointerUp={onPointerUp}
            onKeyDown={onKeyDown}
            style={
              zoom
                ? { transform: `translate(${offset.x}px, ${offset.y}px) scale(${zoomLevel})` }
                : undefined
            }
            className={`max-h-[28rem] max-w-full object-contain focus:outline-primary ${
              zoom ? 'pixelated cursor-grab touch-none active:cursor-grabbing' : ''
            }`}
          />
        ) : (
          <span className="text-xs text-base-content/40">not available yet</span>
        )}
      </div>
    </div>
  )
}
