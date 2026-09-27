import { useEffect, useRef, useState } from 'react'
import { Exhibit } from './Exhibit'
import { Field } from './Field'
import { formatBytes } from '../lib/format'
import { sha256File } from '../lib/hash'

/**
 * File input with drag-and-drop, size readout and an optional SHA-256 chip.
 *
 * The hash follows the `file` prop, not just the user's own picks, so a file
 * handed over from another tab (Protect → Verify, Attack Lab → Verify, a demo
 * sample) gets its chip too. `onHash` reports it so a page can compare it with
 * the hash party A read out.
 */
export function FilePicker({
  label,
  accept,
  hint,
  file,
  onChange,
  showHash = false,
  onHash,
}: {
  label: string
  accept: string
  hint?: string
  file: File | null
  onChange: (file: File | null) => void
  showHash?: boolean
  onHash?: (sha256: string | null) => void
}) {
  const inputRef = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)
  const [hashed, setHashed] = useState<{ file: File; sha256: string } | null>(null)
  // Only trust a digest computed for the file currently shown.
  const hash = file && hashed?.file === file ? hashed.sha256 : null

  useEffect(() => {
    if (!file || !showHash) {
      onHash?.(null)
      return
    }
    let cancelled = false
    void sha256File(file).then((sha256) => {
      if (cancelled) return
      setHashed({ file, sha256 })
      onHash?.(sha256)
    })
    return () => {
      cancelled = true
    }
    // onHash is a callback prop; re-running when a parent re-renders would rehash for nothing.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [file, showHash])

  function select(next: File | null) {
    onChange(next)
    if (inputRef.current) inputRef.current.value = ''
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
          select(e.dataTransfer.files[0] ?? null)
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
                select(null)
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
        onChange={(e) => select(e.target.files?.[0] ?? null)}
      />

      {showHash && hash && (
        <div className="mt-2">
          <Exhibit label="SHA-256">{hash}</Exhibit>
        </div>
      )}
    </Field>
  )
}
