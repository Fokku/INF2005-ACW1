import type { ReactNode } from 'react'

/**
 * Label + optional hint above a form control, and optional help text below.
 *
 * Written in plain Tailwind rather than daisyUI's form classes: daisyUI 5
 * removed `form-control` / `label-text`, and hand-rolling this is three lines.
 *
 * Complete — no TODO.
 */
export function Field({
  label,
  hint,
  help,
  htmlFor,
  children,
}: {
  label: string
  hint?: string
  help?: ReactNode
  htmlFor?: string
  children: ReactNode
}) {
  return (
    <div className="w-full">
      <div className="mb-1 flex items-baseline justify-between gap-2">
        <label htmlFor={htmlFor} className="text-sm font-medium">
          {label}
        </label>
        {hint && <span className="text-xs opacity-60">{hint}</span>}
      </div>
      {children}
      {help && <div className="mt-1 text-xs opacity-60">{help}</div>}
    </div>
  )
}
