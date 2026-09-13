/**
 * Cover and stego video, played back natively.
 *
 * The payload lives in the AVI's PCM audio track, not the frames (see
 * `stego_core/video_codec.py`) — so this is really a listening comparison
 * wearing a video player. Native <video controls> is deliberate for the same
 * reason AudioCompare uses <audio controls>: nothing here needs the decoded
 * samples, and a Web Audio/Canvas pipeline would risk touching the very bits
 * being demonstrated.
 *
 * Complete — no TODO.
 */
export function VideoCompare({
  coverUrl,
  stegoUrl,
}: {
  coverUrl: string | null
  stegoUrl: string | null
}) {
  const clips = [
    { label: 'Cover (original)', url: coverUrl },
    { label: 'Stego (after embedding)', url: stegoUrl },
  ]

  return (
    <div className="space-y-3">
      <div>
        <h3 className="font-stamp text-lg">Playback comparison</h3>
        <p className="text-xs text-base-content/60">
          The frames are byte-identical in both clips — only the audio track carries the payload.
          At 1 or 2 LSBs the difference should be inaudible; raise the LSB count to hear it.
        </p>
      </div>

      {clips.map((clip) => (
        <div key={clip.label} className="space-y-1">
          <span className="text-xs text-base-content/70">{clip.label}</span>
          {clip.url ? (
            <video controls preload="metadata" src={clip.url} className="w-full rounded-sm" />
          ) : (
            <div className="border-base-300 bg-base-200 rounded-sm border p-3 text-xs text-base-content/40">
              not available yet
            </div>
          )}
        </div>
      ))}
    </div>
  )
}
