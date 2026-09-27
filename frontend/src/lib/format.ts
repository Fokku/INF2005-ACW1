/** Small display helpers. Complete — no TODO. */

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
}

export function shortHash(hash: string | null | undefined, chars = 12): string {
  if (!hash) return '—'
  return `${hash.slice(0, chars)}…${hash.slice(-4)}`
}

export function formatDuration(seconds: number): string {
  const m = Math.floor(seconds / 60)
  const s = Math.floor(seconds % 60)
  return `${m}:${s.toString().padStart(2, '0')}`
}

/** A p-value for display: exponent form when tiny, never NaN. */
export function formatP(p: number | null): string {
  if (p === null) return 'n/a'
  if (p === 0) return '< 1e-300'
  return p < 1e-3 ? p.toExponential(1) : p.toFixed(4)
}
