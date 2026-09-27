import { useEffect, useState } from 'react'
import { api } from '../api/client'

/** The browser-playable audio track of an AVI, or null while it loads. */
export function useAviAudioTrack(file: File | null): { url: string | null; error: boolean } {
  const [track, setTrack] = useState<{ file: File; url: string | null; error: boolean } | null>(null)
  useEffect(() => {
    if (!file) return
    let cancelled = false
    api
      .audioTrack(file)
      .then((ref) => !cancelled && setTrack({ file, url: ref.url, error: false }))
      .catch(() => !cancelled && setTrack({ file, url: null, error: true }))
    return () => {
      cancelled = true
    }
  }, [file])
  const current = file && track?.file === file ? track : null
  return { url: current?.url ?? null, error: current?.error ?? false }
}
