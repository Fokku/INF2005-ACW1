import { useEffect, useState } from 'react'
import { api } from '../api/client'
import { CapacityMeter } from '../components/CapacityMeter'
import { DownloadButton } from '../components/DownloadButton'
import { Exhibit } from '../components/Exhibit'
import { Field } from '../components/Field'
import { FilePicker } from '../components/FilePicker'
import { ImageCompare } from '../components/ImageCompare'
import { AudioCompare } from '../components/AudioCompare'
import { VideoCompare } from '../components/VideoCompare'
import { LsbSelector } from '../components/LsbSelector'
import { ErrorNotice } from '../components/NotImplemented'
import { StartLocationPanel } from '../components/StartLocationPanel'
import { StepSection } from '../components/StepSection'
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
  const coverKind = cover?.name.toLowerCase().endsWith('.wav')
    ? 'audio'
    : cover?.name.toLowerCase().endsWith('.avi')
      ? 'video'
      : 'image'
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
    <div className={`grid gap-x-10 gap-y-8 ${cover ? 'lg:grid-cols-2' : ''}`}>
      {/* ---------------- Inputs ---------------- */}
      <section className="space-y-8">
        <StepSection num="1" title="Cover object">
          <FilePicker
            label="Image, audio, or video to protect"
            accept=".png,.wav,.avi"
            hint="PNG, WAV/PCM, or AVI with a PCM audio track"
            file={cover}
            onChange={setCover}
            showHash
          />
          <Field label="Media ID" hint="signed into the payload">
            <input
              className="input font-exhibit w-full"
              placeholder={cover?.name ?? 'e.g. Px-x-lena-001'}
              value={mediaId}
              onChange={(e) => setMediaId(e.target.value)}
            />
          </Field>
        </StepSection>

        <StepSection num="2" title="Message to hide">
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
            className="textarea font-exhibit h-32 w-full text-sm"
            value={messageText}
            onChange={(e) => setMessageText(e.target.value)}
          />
          <div className="flex items-center justify-between">
            <label className="flex cursor-pointer items-center gap-2 text-sm">
              <input
                type="checkbox"
                className="checkbox checkbox-sm checkbox-primary"
                checked={encrypt}
                onChange={(e) => setEncrypt(e.target.checked)}
              />
              <span>Encrypt message (AES-256-GCM)</span>
            </label>
            <span className="font-exhibit text-xs text-base-content/60">{messageBytes} bytes</span>
          </div>
        </StepSection>

        <StepSection num="3" title="Embedding settings">
          <LsbSelector value={nLsb} onChange={setNLsb} />
          <CapacityMeter report={capacity} messageBytes={messageBytes} />
          <StartLocationPanel
            showEncryptionPassphrase={encrypt}
            mode={startMode}
            onModeChange={setStartMode}
            passphrase={passphrase}
            onPassphraseChange={setPassphrase}
            explicitStart={explicitStart}
            onExplicitStartChange={setExplicitStart}
            maxStart={capacity?.total_elements}
          />
        </StepSection>

        <StepSection num="4" title="Signing key">
          <FilePicker
            label="Private key (PEM)"
            accept=".pem"
            hint="demo key from the Keys tab"
            file={privateKey}
            onChange={setPrivateKey}
          />
          <Field label="Team metadata (JSON)">
            <input
              className="input font-exhibit w-full text-sm"
              value={metadataJson}
              onChange={(e) => setMetadataJson(e.target.value)}
            />
          </Field>
        </StepSection>

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
      {cover && (
        <section className="space-y-6">
          {error != null && <ErrorNotice error={error} />}

          {result && (
            <>
              <DownloadButton file={result.stego} />
              <div>
                <h2 className="font-stamp mb-3 text-lg">Embedding report</h2>
                <div className="grid gap-3 sm:grid-cols-2">
                  <Exhibit label="Start offset">
                    element {result.start_offset.toLocaleString()} ({result.start_mode})
                  </Exhibit>
                  <Exhibit label="Frame size">{result.frame_bytes} bytes</Exhibit>
                  <Exhibit label="Capacity used">
                    {((result.frame_bytes / result.capacity_bytes) * 100).toFixed(2)}%
                  </Exhibit>
                  <Exhibit label="Media hash">{result.payload.media_hash}</Exhibit>
                  <Exhibit label="Signature">{result.signature_b64}</Exhibit>
                </div>
              </div>
            </>
          )}

          {coverKind === 'audio' ? (
            <AudioCompare coverUrl={coverUrl} stegoUrl={result?.stego.url ?? null} />
          ) : coverKind === 'video' ? (
            <VideoCompare coverUrl={coverUrl} stegoUrl={result?.stego.url ?? null} />
          ) : (
            <ImageCompare
              coverUrl={coverUrl}
              stegoUrl={result?.stego.url ?? null}
              diffUrl={result?.diff?.url ?? null}
            />
          )}
        </section>
      )}
    </div>
  )
}
