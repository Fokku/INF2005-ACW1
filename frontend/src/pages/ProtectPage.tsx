import { useEffect, useState } from 'react'
import { api } from '../api/client'
import { CapacityMeter } from '../components/CapacityMeter'
import { DownloadButton } from '../components/DownloadButton'
import { Field } from '../components/Field'
import { FilePicker } from '../components/FilePicker'
import { ImageCompare } from '../components/ImageCompare'
import { AudioCompare } from '../components/AudioCompare'
import { LsbSelector } from '../components/LsbSelector'
import { ErrorNotice } from '../components/NotImplemented'
import { StartLocationPanel } from '../components/StartLocationPanel'
import { SAMPLE_PAYLOADS } from '../lib/samplePayloads'
import type { CapacityReport, ProtectResult, StartMode } from '../types'

/**
 * Party A: hide a signed verification payload inside a cover object.
 *
 * Covers steps 1 to 6 of the required security workflow.
 *
 * The page is COMPLETE: state, validation and the API calls all work. It shows
 * a "not implemented" notice today because the backend core is stubbed. No
 * changes are needed here when the core lands.
 */
export function ProtectPage() {
  const [cover, setCover] = useState<File | null>(null)
  const [privateKey, setPrivateKey] = useState<File | null>(null)
  const [messageText, setMessageText] = useState(SAMPLE_PAYLOADS[0].text)
  const [nLsb, setNLsb] = useState(1)
  const [mediaId, setMediaId] = useState('')
  const [metadataJson, setMetadataJson] = useState('{"team": "Px-x", "purpose": "release check"}')
  const [startMode, setStartMode] = useState<StartMode>('derived')
  const [passphrase, setPassphrase] = useState('')
  const [explicitStart, setExplicitStart] = useState(1024)
  const [encrypt, setEncrypt] = useState(false)

  const [capacityData, setCapacityData] = useState<CapacityReport | null>(null)
  const [result, setResult] = useState<ProtectResult | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)

  const coverUrl = cover ? URL.createObjectURL(cover) : null
  const coverKind = cover?.name.toLowerCase().endsWith('.wav') ? 'audio' : 'image'
  const messageBytes = new TextEncoder().encode(messageText).length

  // Derived, not stored: with no cover there is nothing to report, and deriving
  // it here avoids resetting state from inside the effect below.
  const capacity = cover ? capacityData : null

  // Re-check capacity whenever the cover or the LSB count changes, so the user
  // sees "this will not fit" before pressing Protect.
  useEffect(() => {
    if (!cover) return
    let cancelled = false
    api
      .capacity({ cover, nLsb, payloadBytes: messageBytes })
      .then((report) => {
        if (!cancelled) setCapacityData(report)
      })
      .catch(() => {
        if (!cancelled) setCapacityData(null)
      })
    return () => {
      cancelled = true
    }
  }, [cover, nLsb, messageBytes])

  async function onProtect() {
    if (!cover) return
    setBusy(true)
    setError(null)
    setResult(null)
    try {
      setResult(
        await api.protect({
          cover,
          messageText,
          messageMime: 'text/plain',
          nLsb,
          mediaId: mediaId || cover.name,
          metadataJson,
          startMode,
          explicitStart: startMode === 'explicit' ? explicitStart : undefined,
          passphrase: passphrase || undefined,
          encryptMessage: encrypt,
          privateKeyPem: privateKey ?? undefined,
        }),
      )
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      {/* ---------------- Inputs ---------------- */}
      <section className="space-y-4">
        <div className="card bg-base-100 shadow-sm">
          <div className="card-body gap-4">
            <h2 className="card-title text-base">1 · Cover object</h2>
            <FilePicker
              label="Image or audio to protect"
              accept=".png,.wav,image/png,audio/wav"
              hint="PNG or WAV/PCM"
              file={cover}
              onChange={setCover}
              showHash
            />
            <Field label="Media ID" hint="signed into the payload">
              <input
                className="input w-full font-mono"
                placeholder={cover?.name ?? 'e.g. Px-x-lena-001'}
                value={mediaId}
                onChange={(e) => setMediaId(e.target.value)}
              />
            </Field>
          </div>
        </div>

        <div className="card bg-base-100 shadow-sm">
          <div className="card-body gap-4">
            <h2 className="card-title text-base">2 · Message to hide</h2>
            <div className="flex flex-wrap gap-2">
              {SAMPLE_PAYLOADS.map((sample) => (
                <button
                  key={sample.id}
                  type="button"
                  className="btn btn-outline btn-xs"
                  onClick={() => setMessageText(sample.text)}
                  title={sample.description}
                >
                  {sample.label}
                </button>
              ))}
            </div>
            <textarea
              className="textarea h-32 w-full font-mono text-sm"
              value={messageText}
              onChange={(e) => setMessageText(e.target.value)}
            />
            <div className="flex items-center justify-between">
              <label className="flex cursor-pointer items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  className="checkbox checkbox-sm"
                  checked={encrypt}
                  onChange={(e) => setEncrypt(e.target.checked)}
                />
                <span>Encrypt message (AES-256-GCM)</span>
              </label>
              <span className="text-xs opacity-60">{messageBytes} bytes</span>
            </div>
          </div>
        </div>

        <div className="card bg-base-100 shadow-sm">
          <div className="card-body gap-4">
            <h2 className="card-title text-base">3 · Embedding settings</h2>
            <LsbSelector value={nLsb} onChange={setNLsb} />
            <CapacityMeter report={capacity} messageBytes={messageBytes} />
            <StartLocationPanel
              mode={startMode}
              onModeChange={setStartMode}
              passphrase={passphrase}
              onPassphraseChange={setPassphrase}
              explicitStart={explicitStart}
              onExplicitStartChange={setExplicitStart}
              maxStart={capacity?.total_elements}
            />
          </div>
        </div>

        <div className="card bg-base-100 shadow-sm">
          <div className="card-body gap-4">
            <h2 className="card-title text-base">4 · Signing key</h2>
            <FilePicker
              label="Private key (PEM)"
              accept=".pem"
              hint="demo key from the Keys tab"
              file={privateKey}
              onChange={setPrivateKey}
            />
            <Field label="Team metadata (JSON)">
              <input
                className="input w-full font-mono text-sm"
                value={metadataJson}
                onChange={(e) => setMetadataJson(e.target.value)}
              />
            </Field>
          </div>
        </div>

        <button
          type="button"
          className="btn btn-primary w-full"
          disabled={!cover || busy}
          onClick={() => void onProtect()}
        >
          {busy && <span className="loading loading-spinner loading-sm" />}
          Protect and sign
        </button>
      </section>

      {/* ---------------- Results ---------------- */}
      <section className="space-y-4">
        {error != null && <ErrorNotice error={error} />}

        {result && (
          <>
            <DownloadButton file={result.stego} />
            <div className="card bg-base-100 shadow-sm">
              <div className="card-body">
                <h2 className="card-title text-base">Embedding report</h2>
                <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
                  <dt className="opacity-60">Start offset</dt>
                  <dd className="font-mono">
                    element {result.start_offset.toLocaleString()} ({result.start_mode})
                  </dd>
                  <dt className="opacity-60">Frame size</dt>
                  <dd className="font-mono">{result.frame_bytes} bytes</dd>
                  <dt className="opacity-60">Capacity used</dt>
                  <dd className="font-mono">
                    {((result.frame_bytes / result.capacity_bytes) * 100).toFixed(2)}%
                  </dd>
                  <dt className="opacity-60">Media hash</dt>
                  <dd className="font-mono break-all">{result.payload.media_hash}</dd>
                  <dt className="opacity-60">Signature</dt>
                  <dd className="font-mono break-all">{result.signature_b64}</dd>
                </dl>
              </div>
            </div>
          </>
        )}

        <div className="card bg-base-100 shadow-sm">
          <div className="card-body">
            {coverKind === 'audio' ? (
              <AudioCompare coverUrl={coverUrl} stegoUrl={result?.stego.url ?? null} />
            ) : (
              <ImageCompare
                coverUrl={coverUrl}
                stegoUrl={result?.stego.url ?? null}
                diffUrl={result?.diff?.url ?? null}
              />
            )}
          </div>
        </div>
      </section>
    </div>
  )
}
