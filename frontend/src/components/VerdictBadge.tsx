import type { Verdict } from '../types'

/**
 * The verdict, rendered as a full-width stamp — the single most important
 * visual moment in the app (see docs/design/gui-design.md §4). Color + a
 * short stamped word, readable from across a room, never buried in prose.
 *
 * Complete — no TODO. Literal class strings on purpose: Tailwind v4 only
 * emits classes it can see in the source, so building them at runtime would
 * produce unstyled output.
 */

const VERDICT_STYLE: Record<Verdict, { text: string; bg: string; border: string; glyph: string }> = {
  Authentic: {
    text: 'text-verdict-authentic',
    bg: 'bg-verdict-authentic/15',
    border: 'border-verdict-authentic',
    glyph: '▣',
  },
  Tampered: {
    text: 'text-verdict-tampered',
    bg: 'bg-verdict-tampered/15',
    border: 'border-verdict-tampered',
    glyph: '✕',
  },
  'Signature Invalid': {
    text: 'text-verdict-invalid',
    bg: 'bg-verdict-invalid/15',
    border: 'border-verdict-invalid',
    glyph: '✕',
  },
  'Payload Missing': {
    text: 'text-verdict-missing',
    bg: 'bg-verdict-missing/15',
    border: 'border-verdict-missing',
    glyph: '∅',
  },
  'Wrong Start Location': {
    text: 'text-verdict-location',
    bg: 'bg-verdict-location/15',
    border: 'border-verdict-location',
    glyph: '⌖',
  },
  'Cannot Verify': {
    text: 'text-verdict-unknown',
    bg: 'bg-verdict-unknown/15',
    border: 'border-verdict-unknown',
    glyph: '?',
  },
}

const VERDICT_SENTENCE: Record<Verdict, string> = {
  Authentic: 'Hash and signature match. Nothing has changed since protection.',
  Tampered: 'The embedded data is damaged, or the media does not match its signed information. See the checks below.',
  'Signature Invalid': 'Payload found, but the signature does not verify against this public key.',
  'Payload Missing': 'No embedded payload found anywhere in this file.',
  'Wrong Start Location': 'A payload exists, but not at the location this key/offset derives.',
  'Cannot Verify': 'Verification could not reach a conclusion — see the detail below.',
}

export function VerdictBadge({ verdict, reasons }: { verdict: Verdict; reasons?: string[] }) {
  const style = VERDICT_STYLE[verdict]
  return (
    <div className={`border ${style.border} ${style.bg} rounded-sm p-5`}>
      <div className="flex items-baseline gap-3">
        <span className={`font-stamp text-3xl leading-none ${style.text}`} aria-hidden>
          {style.glyph}
        </span>
        <h3 className={`font-stamp text-3xl leading-none ${style.text}`}>{verdict}</h3>
      </div>
      <p className="mt-2 text-sm text-base-content/70">{VERDICT_SENTENCE[verdict]}</p>
      {reasons && reasons.length > 0 && (
        <ul className="mt-3 list-inside list-disc space-y-1 text-sm text-base-content/70">
          {reasons.map((reason, i) => (
            <li key={i}>{reason}</li>
          ))}
        </ul>
      )}
    </div>
  )
}

export function VerdictChip({ verdict }: { verdict: Verdict }) {
  const style = VERDICT_STYLE[verdict]
  return (
    <span
      className={`font-stamp inline-flex items-center gap-1.5 rounded-sm border px-2 py-0.5 text-xs ${style.text} ${style.bg} ${style.border}`}
    >
      <span aria-hidden>{style.glyph}</span>
      {verdict}
    </span>
  )
}
