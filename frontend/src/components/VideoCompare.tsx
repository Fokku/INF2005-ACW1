import { useEffect, useState } from 'react'
import { fetchAsFile } from '../api/client'
import { useAviAudioTrack } from '../lib/useAviAudioTrack'

/**
 * Cover and stego video, compared by ear.
 *
 * The payload lives in the AVI's PCM audio track, not the frames (see
 * `stego_core/video_codec.py`), and browsers cannot play AVI at all — a
 * `<video>` element would stay blank. So each clip's audio track is pulled
 * out server-side as a WAV (POST /api/preview/audio-track) and played with
 * native `<audio controls>`, for the same reason AudioCompare uses it: nothing
 * in the browser touches the samples.
 */

function Track({ label, file }: { label: string; file: File | null }) {
  const { url, error } = useAviAudioTrack(file)
  return (
    <div className="space-y-1">
      <span className="text-xs text-base-content/70">{label}</span>
      {url ? (
        <audio controls preload="metadata" src={url} className="w-full" />
      ) : (
        <div className="border-base-300 bg-base-200 rounded-sm border p-3 text-xs text-base-content/40">
          {!file ? 'not available yet' : error ? 'could not read this AVI’s audio track' : 'extracting the audio track…'}
        </div>
      )}
    </div>
  )
}

export function VideoCompare({
  coverFile,
  stegoUrl,
  stegoName,
}: {
  coverFile: File | null
  stegoUrl: string | null
  stegoName?: string
}) {
  const [stegoFile, setStegoFile] = useState<{ url: string; file: File } | null>(null)
  useEffect(() => {
    if (!stegoUrl) return
    let cancelled = false
    void fetchAsFile(stegoUrl, stegoName ?? 'stego.avi').then((file) => !cancelled && setStegoFile({ url: stegoUrl, file }))
    return () => {
      cancelled = true
    }
  }, [stegoUrl, stegoName])

  return (
    <div className="space-y-3">
      <div>
        <h3 className="font-stamp text-lg">Playback comparison</h3>
        <p className="text-xs text-base-content/60">
          The payload rides in the AVI’s PCM audio track; the video frames are byte-identical. Browsers
          cannot play AVI, so each clip’s audio track is shown here — download the AVI to watch it in
          VLC. At 1 or 2 LSBs the two tracks should sound the same.
        </p>
      </div>
      <Track label="Cover audio track (original)" file={coverFile} />
      <Track
        label="Stego audio track (after embedding)"
        file={stegoUrl && stegoFile?.url === stegoUrl ? stegoFile.file : null}
      />
    </div>
  )
}
