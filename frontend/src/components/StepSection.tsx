import type { ReactNode } from 'react'

/**
 * A numbered case-file step: a square Big Shoulders numeral, a stamped
 * header, and content below — replacing the daisyUI `card` wrapper that
 * nested every section in a bordered box (see docs/design/gui-design.md §3,
 * §7). Sections separate by spacing and a rule, not by boxes inside boxes.
 */
export function StepSection({
  num,
  title,
  children,
}: {
  num: string
  title: string
  children: ReactNode
}) {
  return (
    <section className="border-base-300 border-t pt-6 first:border-t-0 first:pt-0">
      <div className="mb-4 flex items-center gap-3">
        <span className="step-marker">{num}</span>
        <h2 className="font-stamp text-lg">{title}</h2>
      </div>
      <div className="space-y-4 pl-[2.75rem]">{children}</div>
    </section>
  )
}
