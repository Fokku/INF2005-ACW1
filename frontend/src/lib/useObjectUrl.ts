import { useEffect, useState } from 'react'

/**
 * A `blob:` URL for `blob` (a File is a Blob), or null while there is none.
 *
 * The URL is created in the effect and revoked in that same effect's cleanup,
 * then kept in state. Creating it in `useMemo` and revoking it in an effect
 * breaks under StrictMode (pnpm dev): React runs every new effect's setup,
 * cleanup, setup again, so the cleanup revokes the memoized URL and nothing
 * makes a new one. Here the second setup simply creates a fresh URL.
 *
 * The URL is returned only while it belongs to the current `blob`, so a
 * revoked one is never rendered; a new blob shows null for one render.
 */
export function useObjectUrl(blob: Blob | null): string | null {
  const [entry, setEntry] = useState<{ blob: Blob; url: string } | null>(null)
  useEffect(() => {
    if (!blob) return
    const url = URL.createObjectURL(blob)
    // This effect synchronises with an external system (the browser's blob URL
    // registry), and the URL can only be created here, next to its revoke.
    // oxlint-disable-next-line react/set-state-in-effect
    setEntry({ blob, url })
    return () => {
      URL.revokeObjectURL(url)
      setEntry((current) => (current?.url === url ? null : current))
    }
  }, [blob])
  return blob && entry?.blob === blob ? entry.url : null
}
