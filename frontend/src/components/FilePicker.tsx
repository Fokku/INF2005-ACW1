import { useRef, useState } from 'react'
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
        className={`flex cursor-pointer flex-col items-center justify-center gap-1 rounded-lg border-2 border-dashed p-4 text-center transition-colors ${
          dragging ? 'border-primary bg-primary/10' : 'border-base-300 hover:border-primary/50'
        }`}
      >
        {file ? (
          <>
            <span className="font-mono text-sm break-all">{file.name}</span>
            <span className="text-xs opacity-60">{formatBytes(file.size)}</span>
          </>
        ) : (
          <>
            <span className="text-sm opacity-70">Drop a file here, or click to browse</span>
            <span className="text-xs opacity-50">{accept}</span>
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
        <div className="mt-2 flex items-center gap-2 text-xs">
          <span className="badge badge-ghost badge-sm">SHA-256</span>
          <code className="truncate opacity-70">{hash}</code>
        </div>
      )}

      {file && (
        <button type="button" className="btn btn-ghost btn-xs mt-1" onClick={() => void select(null)}>
          Clear
        </button>
      )}
    </Field>
  )
}
