import type { Verdict } from '../types'

/**
 * The verdict, rendered as a coloured alert with its reasons.
 *
 * Complete — no TODO. Note the literal class strings in VERDICT_STYLE: Tailwind
 * v4 only emits classes it can SEE in the source, so building them at runtime
 * (`alert-${kind}`) would produce unstyled output.
 */

const VERDICT_STYLE: Record<Verdict, { alert: string; badge: string; icon: string }> = {
  Authentic: { alert: 'alert-success', badge: 'badge-success', icon: '✓' },
  Tampered: { alert: 'alert-error', badge: 'badge-error', icon: '✗' },
  'Signature Invalid': { alert: 'alert-error', badge: 'badge-error', icon: '✗' },
  'Payload Missing': { alert: 'alert-warning', badge: 'badge-warning', icon: '∅' },
  'Wrong Start Location': { alert: 'alert-warning', badge: 'badge-warning', icon: '⌖' },
  'Cannot Verify': { alert: 'alert-info', badge: 'badge-neutral', icon: '?' },
}

const VERDICT_MEANING: Record<Verdict, string> = {
  Authentic: 'Payload found, signature valid, media hash matches.',
  Tampered: 'The payload is genuine but the media or the payload has been altered since signing.',
  'Signature Invalid': 'A payload was found, but it was not signed by the expected key.',
  'Payload Missing': 'No hidden payload anywhere in this file.',
  'Wrong Start Location': 'A payload exists, but not where the supplied key or offset points.',
  'Cannot Verify': 'Not enough information to judge: unsupported file, or a missing/invalid key.',
}

export function VerdictBadge({ verdict, reasons }: { verdict: Verdict; reasons?: string[] }) {
  const style = VERDICT_STYLE[verdict]
  return (
    <div className={`alert ${style.alert} items-start`}>
      <span className="text-2xl leading-none" aria-hidden>
        {style.icon}
      </span>
      <div className="min-w-0">
        <h3 className="text-lg font-bold">{verdict}</h3>
        <p className="text-sm opacity-90">{VERDICT_MEANING[verdict]}</p>
        {reasons && reasons.length > 0 && (
          <ul className="mt-2 list-inside list-disc space-y-0.5 text-sm opacity-80">
            {reasons.map((reason, i) => (
              <li key={i}>{reason}</li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}

export function VerdictChip({ verdict }: { verdict: Verdict }) {
  return <span className={`badge ${VERDICT_STYLE[verdict].badge} badge-sm`}>{verdict}</span>
}
