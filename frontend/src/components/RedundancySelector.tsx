/**
 * How many copies of the hidden frame to embed (robust embedding, the
 * team's bonus innovation; see backend/stego_core/ecc.py).
 *
 * Party A picks it on Protect and party B must pick the same number on
 * Verify, exactly like the LSB count. The note under the buttons states the
 * trade-off: more copies survive more damage but use more of the cover.
 */

const OPTIONS: { value: number; text: string; tone: string }[] = [
  { value: 1, text: 'One copy. Any damage to the hidden data breaks verification.', tone: 'text-base-content/60' },
  { value: 3, text: '3x the space. Survives mild noise: the other copies outvote a damaged one.', tone: 'text-success' },
  { value: 5, text: '5x the space. Survives heavier noise than 3 copies.', tone: 'text-success' },
]

export function RedundancySelector({
  value,
  onChange,
  disabled,
}: {
  value: number
  onChange: (value: number) => void
  disabled?: boolean
}) {
  const current = OPTIONS.find((option) => option.value === value) ?? OPTIONS[0]
  return (
    <div className="w-full">
      <span className="text-sm font-medium text-base-content/80">Copies embedded (robust embedding)</span>
      <div className="join mt-2 flex">
        {OPTIONS.map((option) => (
          <button
            key={option.value}
            type="button"
            disabled={disabled}
            onClick={() => onChange(option.value)}
            aria-pressed={value === option.value}
            className={`btn btn-sm join-item flex-1 ${value === option.value ? 'btn-primary' : 'btn-outline'}`}
          >
            {option.value === 1 ? '1 (off)' : option.value}
          </button>
        ))}
      </div>
      <p className={`mt-2 text-xs ${current.tone}`}>{current.text}</p>
    </div>
  )
}
