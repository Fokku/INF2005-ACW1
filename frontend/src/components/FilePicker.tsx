import { useRef, useState } from 'react'
import { Exhibit } from './Exhibit'
import { Field } from './Field'
import { formatBytes } from '../lib/format'
import { sha256File } from '../lib/hash'

/**
 * File input with drag-and-drop, size readout and an optional SHA-256 chip.
 * Complete — no TODO.
 */
export function FilePicker({
  label,
  accept,
  hint,
  file,
  onChange,
  showHash = false,
}: {
  label: string
  accept: string
  hint?: string
  file: File | null
  onChange: (file: File | null) => void
  showHash?: boolean
}) {
  const inputRef = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)
  const [hash, setHash] = useState<string | null>(null)

  async function select(next: File | null) {
    onChange(next)
    setHash(null)
    if (next && showHash) setHash(await sha256File(next))
  }

  return (
    <Field label={label} hint={hint}>
      <div
        onDragOver={(e) => {
          e.preventDefault()
          setDragging(true)
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault()
          setDragging(false)
          void select(e.dataTransfer.files[0] ?? null)
        }}
        onClick={() => inputRef.current?.click()}
        className={`relative flex cursor-pointer flex-col items-center justify-center gap-1 rounded-sm border-2 border-dashed p-4 text-center transition-colors ${
          dragging ? 'border-primary bg-primary/10' : 'border-base-300 hover:border-primary/50'
        }`}
      >
        {file ? (
          <>
            <button
              type="button"
              aria-label="Clear selected file"
              title="Clear"
              onClick={(e) => {
                e.stopPropagation()
                void select(null)
              }}
              className="border-base-300 text-base-content/60 hover:border-error hover:text-error hover:bg-error/10 absolute top-2 right-2 flex size-6 items-center justify-center rounded-sm border text-sm leading-none transition-colors"
            >
              ✕
            </button>
            <span className="font-exhibit max-w-[85%] text-sm break-all">{file.name}</span>
            <span className="text-xs text-base-content/60">{formatBytes(file.size)}</span>
          </>
        ) : (
          <>
            <span className="text-sm text-base-content/70">Drop a file here, or click to browse</span>
            <span className="text-xs text-base-content/50">{accept}</span>
          </>
        )}
      </div>

      <input
        ref={inputRef}
        type="file"
        accept={accept}
        className="hidden"
        onChange={(e) => void select(e.target.files?.[0] ?? null)}
      />

      {showHash && hash && (
        <div className="mt-2">
          <Exhibit label="SHA-256">{hash}</Exhibit>
        </div>
      )}
    </Field>
  )
}
