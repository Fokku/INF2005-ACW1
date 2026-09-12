import type { ReactNode } from 'react'

/**
 * A labeled block of byte-level data: hash, hex, offset, nonce, signature.
 *
 * One component for every exhibit-style value in the app (see
 * docs/design/gui-design.md §5) so a hash always looks like a hash, never like
 * inline prose. Values wrap in full — never truncated with an ellipsis, since
 * a marker needs to compare the whole thing across screens.
 */
export function Exhibit({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="exhibit">
      <div className="exhibit__label">{label}</div>
      <div className="exhibit__value">{children}</div>
    </div>
  )
}

/** Two exhibits side by side, for a signed-vs-recomputed hash comparison. */
export function ExhibitPair({
  left,
  right,
}: {
  left: { label: string; value: ReactNode }
  right: { label: string; value: ReactNode }
}) {
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      <Exhibit label={left.label}>{left.value}</Exhibit>
      <Exhibit label={right.label}>{right.value}</Exhibit>
    </div>
  )
}
