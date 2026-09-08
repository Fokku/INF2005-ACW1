/**
 * Cover and stego audio, played back natively.
 *
 * The spec requires the GUI to be able to play the cover and stego objects for
 * comparison. Native <audio controls> is deliberate: a Web Audio pipeline would
 * decode to float32 and destroy the LSBs, and nothing here needs the samples
 * anyway — the backend does all the bit work.
 *
 * Complete — no TODO. A waveform view with wavesurfer.js would be a nice
 * addition once the core works, but it must stay display-only.
 */
export function AudioCompare({
  coverUrl,
  stegoUrl,
}: {
  coverUrl: string | null
  stegoUrl: string | null
}) {
  const tracks = [
    { label: 'Cover (original)', url: coverUrl },
    { label: 'Stego (after embedding)', url: stegoUrl },
  ]

  return (
    <div className="space-y-3">
      <div>
        <span className="font-medium">Listening comparison</span>
        <p className="text-xs opacity-60">
          At 1 or 2 LSBs these should be indistinguishable. Raise the LSB count and the hiss becomes
          obvious — that is the capacity versus perceptibility trade-off.
        </p>
      </div>

      {tracks.map((track) => (
        <div key={track.label} className="space-y-1">
          <span className="text-xs opacity-70">{track.label}</span>
          {track.url ? (
            <audio controls preload="metadata" src={track.url} className="w-full" />
          ) : (
            <div className="rounded-lg border border-base-300 bg-base-200 p-3 text-xs opacity-40">
              not available yet
            </div>
          )}
        </div>
      ))}
    </div>
  )
}
