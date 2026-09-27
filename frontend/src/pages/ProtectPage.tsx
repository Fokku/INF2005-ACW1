import { useEffect, useMemo, useState } from 'react'
import { api, fetchAsFile } from '../api/client'
import { CapacityMeter } from '../components/CapacityMeter'
import { DownloadButton } from '../components/DownloadButton'
import { Exhibit } from '../components/Exhibit'
import { Field } from '../components/Field'
import { FilePicker } from '../components/FilePicker'
import { HandoffCard } from '../components/HandoffCard'
import { ImageCompare } from '../components/ImageCompare'
import { AudioCompare } from '../components/AudioCompare'
import { VideoCompare } from '../components/VideoCompare'
import { LsbSelector } from '../components/LsbSelector'
import { ErrorNotice } from '../components/NotImplemented'
import { RedundancySelector } from '../components/RedundancySelector'
import { StartLocationPanel } from '../components/StartLocationPanel'
import { StepSection } from '../components/StepSection'
import { SAMPLE_PAYLOADS } from '../lib/samplePayloads'
import type {
  AttackPrefill,
  CapacityReport,
  ProtectHandoff,
  ProtectResult,
  StartMode,
  VerifyPrefill,
} from '../types'

/**
 * Party A: hide a signed verification payload inside a cover object.
 *
 * Covers steps 1 to 6 of the required security workflow. After a successful
 * embed, the hand-off card lists what party B needs and can pass the stego
 * file straight to the Verify tab or the Attack Lab.
 */
export function ProtectPage({
  onProtected,
  onVerify,
  onAttack,
}: {
  onProtected: (handoff: ProtectHandoff) => void
  onVerify: (prefill: Omit<VerifyPrefill, 'id'>) => void
  onAttack: (prefill: Omit<AttackPrefill, 'id'>) => void
}) {
  const [cover, setCover] = useState<File | null>(null)
  const [privateKey, setPrivateKey] = useState<File | null>(null)
  const [messageText, setMessageText] = useState(SAMPLE_PAYLOADS[0].text)
  const [nLsb, setNLsb] = useState(1)
  const [mediaId, setMediaId] = useState('')
  const [metadataJson, setMetadataJson] = useState('{"team": "INF2005 ACW1", "purpose": "release check"}')
  const [startMode, setStartMode] = useState<StartMode>('derived')
  const [passphrase, setPassphrase] = useState('')
  const [explicitStart, setExplicitStart] = useState(1024)
  const [encrypt, setEncrypt] = useState(false)
  const [seal, setSeal] = useState(false)
  const [redundancy, setRedundancy] = useState(1)

  const [capacityData, setCapacityData] = useState<CapacityReport | null>(null)
  const [result, setResult] = useState<ProtectResult | null>(null)
  // The settings the current result was produced with (the form may change afterwards).
  const [resultSettings, setResultSettings] = useState<{ mediaId: string; startMode: StartMode } | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)
  const [handingOff, setHandingOff] = useState(false)

  const coverUrl = useMemo(() => (cover ? URL.createObjectURL(cover) : null), [cover])
  useEffect(() => () => {
    if (coverUrl) URL.revokeObjectURL(coverUrl)
  }, [coverUrl])

  const coverKind = cover?.name.toLowerCase().endsWith('.wav')
    ? 'audio'
    : cover?.name.toLowerCase().endsWith('.avi')
      ? 'video'
      : 'image'
  const messageBytes = new TextEncoder().encode(messageText).length

  // Derived, not stored: with no cover there is nothing to report, and deriving
  // it here avoids resetting state from inside the effect below.
  const capacity = cover ? capacityData : null

  // Re-check capacity whenever the cover, the LSB count, the number of copies
  // or the seal changes, so the user sees "this will not fit" before pressing Protect.
  useEffect(() => {
    if (!cover) return
    let cancelled = false
    api
      .capacity({ cover, nLsb, payloadBytes: messageBytes, redundancy, sealFrame: seal })
      .then((report) => {
        if (!cancelled) setCapacityData(report)
      })
      .catch(() => {
        if (!cancelled) setCapacityData(null)
      })
    return () => {
      cancelled = true
    }
  }, [cover, nLsb, messageBytes, redundancy, seal])

  const needsPassphrase = startMode === 'derived' || encrypt || seal
  const blocker = !cover
    ? 'Choose a cover object.'
    : !mediaId.trim()
      ? 'Enter a media ID.'
      : !privateKey
        ? 'Choose the private key that signs the payload.'
        : needsPassphrase && !passphrase
          ? startMode === 'derived'
            ? 'Enter the shared passphrase: the derived start location needs it.'
            : 'Enter the shared passphrase: encryption and sealing need it.'
          : null

  function chooseCover(next: File | null) {
    setCover(next)
    setResult(null)
    setError(null)
    // The media ID is signed into the payload and must match on Verify, so
    // show the default instead of hiding it in a placeholder.
    if (next && (!mediaId || mediaId === cover?.name)) setMediaId(next.name)
  }

  async function onProtect() {
    if (!cover || blocker) return
    setBusy(true)
    setError(null)
    setResult(null)
    try {
      const protectedResult = await api.protect({
        cover,
        messageText,
        messageMime: 'text/plain',
        nLsb,
        mediaId: mediaId.trim(),
        metadataJson,
        startMode,
        explicitStart: startMode === 'explicit' ? explicitStart : undefined,
        passphrase: passphrase || undefined,
        encryptMessage: encrypt,
        privateKeyPem: privateKey ?? undefined,
        redundancy,
        sealFrame: seal,
      })
      setResult(protectedResult)
      setResultSettings({ mediaId: mediaId.trim(), startMode })
      onProtected({ result: protectedResult, mediaId: mediaId.trim(), startMode })
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }

  async function handOff(target: 'verify' | 'attack') {
    if (!result || !resultSettings) return
    setHandingOff(true)
    try {
      const file = await fetchAsFile(result.stego.url, result.stego.filename, result.stego.mime)
      if (target === 'verify') {
        onVerify({
          source: 'Protect tab',
          file,
          mediaId: resultSettings.mediaId,
          nLsb: result.n_lsb,
          redundancy: result.redundancy,
          startMode: resultSettings.startMode,
          explicitStart: resultSettings.startMode === 'explicit' ? result.start_offset : null,
          publicKeyPem: result.signer_public_key_pem,
          publicKeyLabel: `signer key ${result.signer_fingerprint.slice(0, 12)}…`,
          expectedSha256: result.stego.sha256,
          note: resultSettings.startMode === 'derived' || result.payload.message_encrypted || result.sealed
            ? 'Type the shared passphrase — it never travels with the file.'
            : null,
        })
      } else {
        onAttack({
          source: 'Protect tab',
          file,
          nLsb: result.n_lsb,
          startOffset: result.start_offset,
          mediaId: resultSettings.mediaId,
          redundancy: result.redundancy,
          sealed: result.sealed,
          publicKeyPem: result.signer_public_key_pem,
          publicKeyLabel: `signer key ${result.signer_fingerprint.slice(0, 12)}…`,
        })
      }
    } catch (err) {
      setError(err)
    } finally {
      setHandingOff(false)
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
            onChange={chooseCover}
            showHash
          />
          <Field
            label="Media ID"
            hint="signed into the payload"
            help="Party B must type exactly this. It also salts the passphrase, so a different media ID derives a different start."
          >
            <input
              className="input font-exhibit w-full"
              placeholder="e.g. P6-8-cover-001"
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
                onClick={() => {
                  setMessageText(sample.text)
                  // The custom payload is the confidential one (spec Section 5).
                  if (sample.id === 'custom') setEncrypt(true)
                }}
                title={sample.description}
              >
                {sample.label}
              </button>
            ))}
          </div>
          <textarea
            aria-label="Message to hide"
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
          <RedundancySelector value={redundancy} onChange={setRedundancy} />
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
            seal={seal}
            onSealChange={setSeal}
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
          <Field label="Team metadata (JSON)" hint="signed into the payload">
            <input
              className="input font-exhibit w-full text-sm"
              value={metadataJson}
              onChange={(e) => setMetadataJson(e.target.value)}
            />
          </Field>
        </StepSection>

        <div className="space-y-2">
          <button
            type="button"
            className="btn btn-primary w-full"
            disabled={Boolean(blocker) || busy}
            onClick={() => void onProtect()}
          >
            {busy && <span className="loading loading-spinner loading-sm" />}
            Protect and sign
          </button>
          {blocker && cover && <p className="text-center text-xs text-base-content/60">{blocker}</p>}
        </div>
      </section>

      {/* ---------------- Results ---------------- */}
      {cover && (
        <section className="space-y-6">
          {error != null && <ErrorNotice error={error} />}

          {result && resultSettings && (
            <>
              <DownloadButton file={result.stego} />
              <HandoffCard
                result={result}
                mediaId={resultSettings.mediaId}
                startMode={resultSettings.startMode}
                busy={handingOff}
                onVerify={() => void handOff('verify')}
                onAttack={() => void handOff('attack')}
              />
              <div>
                <h2 className="font-stamp mb-3 text-lg">Embedding report</h2>
                <div className="grid gap-3 sm:grid-cols-2">
                  <Exhibit label="Start offset">
                    element {result.start_offset.toLocaleString()} ({result.start_mode})
                  </Exhibit>
                  <Exhibit label="Frame size">
                    {result.frame_bytes} bytes{result.sealed ? ' (sealed)' : ''}
                  </Exhibit>
                  <Exhibit label="Copies embedded">
                    {result.redundancy === 1 ? '1 (robust embedding off)' : result.redundancy}
                  </Exhibit>
                  <Exhibit label="Capacity used">
                    {(((result.frame_bytes * result.redundancy) / result.capacity_bytes) * 100).toFixed(2)}%
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
            <VideoCompare coverFile={cover} stegoUrl={result?.stego.url ?? null} stegoName={result?.stego.filename} />
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
