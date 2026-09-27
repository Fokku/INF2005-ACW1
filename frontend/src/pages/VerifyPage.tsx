import { useEffect, useState } from 'react'
import { api, fetchAsFile } from '../api/client'
import { Exhibit } from '../components/Exhibit'
import { Field } from '../components/Field'
import { FilePicker } from '../components/FilePicker'
import { LsbSelector } from '../components/LsbSelector'
import { ErrorNotice } from '../components/NotImplemented'
import { PayloadPreview } from '../components/PayloadPreview'
import { RedundancySelector } from '../components/RedundancySelector'
import { ReportPanel } from '../components/ReportPanel'
import { StartLocationPanel } from '../components/StartLocationPanel'
import { StepSection } from '../components/StepSection'
import { VerdictBadge, VerdictChip } from '../components/VerdictBadge'
import { useAviAudioTrack } from '../lib/useAviAudioTrack'
import { useObjectUrl } from '../lib/useObjectUrl'
import type { PublicKeyFile, SampleCase, StartMode, Verdict, VerifyPrefill, VerifyReport } from '../types'

/**
 * Party B: check a received file and say whether it is authentic.
 *
 * Covers steps 7 to 10 of the required security workflow. Settings can arrive
 * three ways: typed by party B, handed over by another tab (`prefill`), or
 * loaded with a curated sample from samples/ — the demo's fallback path.
 */

/** Protect names its output `<cover>.stego.png` and the Attack Lab appends
 * `.<attack>`; the media ID Protect defaults to is the cover's own file name. */
function guessMediaId(filename: string): string {
  const match = /^(.*?)\.stego(?:\.[^.]+)*?(\.[^.]+)$/.exec(filename)
  return match ? `${match[1]}${match[2]}` : filename
}

const HINTS: Partial<Record<Verdict, string[]>> = {
  'Wrong Start Location': [
    'Derived start: the passphrase and the media ID must both match party A exactly (the media ID salts the passphrase).',
    'Explicit start: the offset must be the one party A used.',
  ],
  'Payload Missing': [
    'Check the LSB count and the number of copies — they must match party A.',
    'A sealed frame with a wrong passphrase or media ID looks exactly like no payload.',
    'Re-encoded or messaging-app copies lose the LSB plane. Compare the SHA-256 with party A’s.',
  ],
  'Signature Invalid': ['Check the public key fingerprint with party A.'],
  Tampered: [
    'Compare the file’s SHA-256 with the one party A read out: if it differs, the file changed in transit.',
    'A different media ID than the one signed also reports Tampered.',
  ],
  'Cannot Verify': [
    'Check the LSB count, the passphrase or explicit offset, and the media ID.',
    'Large covers are only scanned up to a limit, so absence cannot always be proven.',
    'A sealed frame with a wrong passphrase or media ID cannot be found at all: on a large cover that ends here rather than at Payload Missing.',
  ],
}

export function VerifyPage({ prefill }: { prefill: VerifyPrefill | null }) {
  const [stego, setStego] = useState<File | null>(null)
  const [stegoSha, setStegoSha] = useState<string | null>(null)
  const [expectedSha, setExpectedSha] = useState('')
  const [publicKeyFile, setPublicKeyFile] = useState<File | null>(null)
  const [publicKeyText, setPublicKeyText] = useState('')
  const [publicKeyLabel, setPublicKeyLabel] = useState<string | null>(null)
  const [fingerprint, setFingerprint] = useState<string | null>(null)
  const [nLsb, setNLsb] = useState(1)
  const [mediaId, setMediaId] = useState('')
  const [mediaIdAuto, setMediaIdAuto] = useState(true)
  const [startMode, setStartMode] = useState<StartMode>('derived')
  const [passphrase, setPassphrase] = useState('')
  const [explicitStart, setExplicitStart] = useState(1024)
  const [redundancy, setRedundancy] = useState(1)
  // Set by a hand-off whose file has a sealed frame: without the passphrase
  // the frame cannot even be found, so explicit mode needs one too.
  const [requiresPassphrase, setRequiresPassphrase] = useState(false)
  const [source, setSource] = useState<{ label: string; expected?: Verdict | null; note?: string | null } | null>(
    null,
  )

  const [samples, setSamples] = useState<SampleCase[]>([])
  const [publicKeys, setPublicKeys] = useState<PublicKeyFile[]>([])
  const [report, setReport] = useState<VerifyReport | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    api.samples().then(setSamples).catch(() => setSamples([]))
    api.publicKeys().then(setPublicKeys).catch(() => setPublicKeys([]))
  }, [])

  // Apply a hand-off from another tab once per id (so the same settings can be
  // sent twice in a row), while rendering rather than in an effect.
  const [appliedPrefill, setAppliedPrefill] = useState<number | null>(null)
  if (prefill && prefill.id !== appliedPrefill) {
    setAppliedPrefill(prefill.id)
    setStego(prefill.file)
    setMediaId(prefill.mediaId)
    setMediaIdAuto(false)
    setNLsb(prefill.nLsb)
    setRedundancy(prefill.redundancy)
    setStartMode(prefill.startMode)
    if (prefill.explicitStart !== null && prefill.explicitStart !== undefined) setExplicitStart(prefill.explicitStart)
    // The passphrase never travels with a file. When this one needs it, keep a
    // passphrase party B already typed instead of wiping it; otherwise start
    // clean so a stale one cannot leak into an unrelated check.
    if (prefill.passphrase || !prefill.requiresPassphrase) setPassphrase(prefill.passphrase ?? '')
    setRequiresPassphrase(Boolean(prefill.requiresPassphrase))
    if (prefill.publicKeyPem) {
      setPublicKeyFile(null)
      setPublicKeyText(prefill.publicKeyPem)
      setPublicKeyLabel(prefill.publicKeyLabel ?? null)
    }
    setExpectedSha(prefill.expectedSha256 ?? '')
    setSource({ label: prefill.source, expected: prefill.expectedVerdict, note: prefill.note })
    setReport(null)
    setError(null)
  }

  // Fingerprint of whichever public key is active, so party B can read it back
  // to party A before trusting a verdict.
  useEffect(() => {
    let cancelled = false
    const load = publicKeyFile ? publicKeyFile.text() : Promise.resolve(publicKeyText)
    void load.then((pem) => {
      if (!pem.includes('BEGIN PUBLIC KEY')) {
        if (!cancelled) setFingerprint(null)
        return
      }
      api
        .inspectKey(pem)
        .then((info) => !cancelled && setFingerprint(info.fingerprint))
        .catch(() => !cancelled && setFingerprint(null))
    })
    return () => {
      cancelled = true
    }
  }, [publicKeyFile, publicKeyText])

  const stegoUrl = useObjectUrl(stego)
  const isAudio = stego?.name.toLowerCase().endsWith('.wav') ?? false
  const isVideo = stego?.name.toLowerCase().endsWith('.avi') ?? false

  const expected = expectedSha.trim().toLowerCase()
  const shaMatch = expected && stegoSha ? expected === stegoSha : null

  const hasKey = Boolean(publicKeyFile) || publicKeyText.trim().length > 0
  const blocker = !stego
    ? 'Choose the file you received.'
    : !mediaId.trim()
      ? 'Enter the media ID agreed with the sender.'
      : !hasKey
        ? 'Choose or paste the sender’s public key.'
        : startMode === 'derived' && !passphrase
          ? 'Enter the shared passphrase: the derived start location needs it.'
          : requiresPassphrase && !passphrase
            ? 'Enter the shared passphrase: this file’s frame is sealed, and a sealed frame cannot be found without it.'
            : null

  function chooseFile(next: File | null) {
    setStego(next)
    setReport(null)
    setError(null)
    setSource(null)
    setRequiresPassphrase(false)
    if (next && (mediaIdAuto || !mediaId)) {
      setMediaId(guessMediaId(next.name))
      setMediaIdAuto(true)
    }
  }

  function selectPublicKey(name: string) {
    const key = publicKeys.find((k) => k.name === name)
    if (!key) return
    setPublicKeyFile(null)
    setPublicKeyText(key.public_key_pem)
    setPublicKeyLabel(`keys/public/${key.name}`)
  }

  async function loadSample(id: string) {
    const sample = samples.find((s) => s.id === id)
    if (!sample) return
    setError(null)
    try {
      const file = await fetchAsFile(sample.url, sample.file.split('/').pop() ?? sample.id)
      setStego(file)
      setMediaId(sample.media_id)
      setMediaIdAuto(false)
      setNLsb(sample.n_lsb)
      setRedundancy(sample.redundancy)
      setStartMode(sample.start_mode)
      if (sample.explicit_start !== null) setExplicitStart(sample.explicit_start)
      setPassphrase(sample.passphrase ?? '')
      setRequiresPassphrase(false)
      selectPublicKey(sample.public_key)
      setExpectedSha('')
      setSource({ label: `Sample · ${sample.file}`, expected: sample.expected_verdict, note: sample.note })
      setReport(null)
    } catch (err) {
      setError(err)
    }
  }

  async function onVerify() {
    if (!stego || blocker) return
    setBusy(true)
    setError(null)
    setReport(null)
    try {
      setReport(
        await api.verify({
          stego,
          publicKeyFile: publicKeyFile ?? undefined,
          publicKeyText: publicKeyFile ? undefined : publicKeyText || undefined,
          nLsb,
          mediaId: mediaId.trim(),
          startMode,
          explicitStart: startMode === 'explicit' ? explicitStart : undefined,
          passphrase: passphrase || undefined,
          redundancy,
        }),
      )
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="grid gap-x-10 gap-y-8 lg:grid-cols-2">
      {/* ---------------- Inputs ---------------- */}
      <section className="space-y-8">
        {samples.length > 0 && (
          <Field
            label="Load a demo sample"
            hint="samples/ · settings filled in"
            help="Each curated sample comes with the exact settings that reproduce its verdict (README, “Expected outputs”)."
          >
            <select
              aria-label="Load a demo sample"
              className="select w-full"
              value=""
              onChange={(e) => void loadSample(e.target.value)}
            >
              <option value="" disabled>
                Choose a sample…
              </option>
              {(['image', 'audio', 'video'] as const).map((kind) => {
                const group = samples.filter((s) => s.kind === kind)
                if (group.length === 0) return null
                return (
                  <optgroup key={kind} label={kind === 'image' ? 'Image (PNG)' : kind === 'audio' ? 'Audio (WAV)' : 'Video (AVI)'}>
                    {group.map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.label} → {s.expected_verdict}
                      </option>
                    ))}
                  </optgroup>
                )
              })}
            </select>
          </Field>
        )}

        <StepSection num="1" title="The file you received">
          {source && (
            <div className="border-primary/60 bg-primary/10 space-y-1 rounded-sm border px-3 py-2 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <span>
                  Loaded from <span className="font-medium">{source.label}</span>
                </span>
                {source.expected && (
                  <>
                    <span className="text-base-content/60">· expected</span>
                    <VerdictChip verdict={source.expected} />
                  </>
                )}
              </div>
              {source.note && <p className="text-xs text-base-content/70">{source.note}</p>}
            </div>
          )}
          <FilePicker
            label="Stego image, audio, or video"
            accept=".png,.wav,.avi"
            hint="the file as it arrived"
            file={stego}
            onChange={chooseFile}
            onHash={setStegoSha}
            showHash
          />
          <Field
            label="SHA-256 party A read out"
            hint="optional"
            help="Paste the hash from party A's download card. A match proves the bytes survived the transfer."
          >
            <input
              className="input font-exhibit w-full text-xs"
              placeholder="64 hex characters"
              value={expectedSha}
              onChange={(e) => setExpectedSha(e.target.value)}
            />
          </Field>
          {shaMatch !== null && (
            <p
              role="status"
              className={`font-stamp text-base ${shaMatch ? 'text-verdict-authentic' : 'text-verdict-tampered'}`}
            >
              {shaMatch ? '✓ Same bytes as party A sent' : '✕ Different bytes — the file changed in transit'}
            </p>
          )}
          <Field
            label="Media ID"
            hint="agreed with the sender"
            help={mediaIdAuto && stego ? 'Guessed from the file name. Replace it if party A used another ID.' : undefined}
          >
            <input
              className="input font-exhibit w-full"
              placeholder="e.g. P6-8-cover-001"
              value={mediaId}
              onChange={(e) => {
                setMediaId(e.target.value)
                setMediaIdAuto(false)
              }}
            />
          </Field>
        </StepSection>

        <StepSection num="2" title="Public key">
          {publicKeys.length > 0 && (
            <Field label="Team public keys" hint="keys/public/">
              <select
                aria-label="Team public keys"
                className="select w-full"
                value=""
                onChange={(e) => selectPublicKey(e.target.value)}
              >
                <option value="" disabled>
                  Use a committed public key…
                </option>
                {publicKeys.map((k) => (
                  <option key={k.name} value={k.name}>
                    {k.name} · {k.fingerprint.slice(0, 12)}…
                  </option>
                ))}
              </select>
            </Field>
          )}
          <FilePicker
            label="Public key (PEM)"
            accept=".pem"
            hint="or pick a file"
            file={publicKeyFile}
            onChange={(f) => {
              setPublicKeyFile(f)
              setPublicKeyLabel(f ? f.name : null)
            }}
          />
          <div className="divider text-xs">or paste it</div>
          <textarea
            aria-label="Public key PEM"
            className="textarea font-exhibit h-24 w-full text-xs"
            placeholder="-----BEGIN PUBLIC KEY-----"
            value={publicKeyText}
            disabled={Boolean(publicKeyFile)}
            onChange={(e) => {
              setPublicKeyText(e.target.value)
              setPublicKeyLabel(null)
            }}
          />
          {fingerprint && (
            <Exhibit label={`Key fingerprint${publicKeyLabel ? ` · ${publicKeyLabel}` : ''}`}>{fingerprint}</Exhibit>
          )}
        </StepSection>

        <StepSection num="3" title="Extraction settings">
          <LsbSelector value={nLsb} onChange={setNLsb} />
          <RedundancySelector value={redundancy} onChange={setRedundancy} />
          <p className="text-xs text-base-content/60">
            Both the LSB count and the number of copies must match what party A used. Pick a wrong
            number and the frame will not parse.
          </p>
          <StartLocationPanel
            showEncryptionPassphrase
            mode={startMode}
            onModeChange={setStartMode}
            passphrase={passphrase}
            onPassphraseChange={setPassphrase}
            explicitStart={explicitStart}
            onExplicitStartChange={setExplicitStart}
          />
        </StepSection>

        <div className="space-y-2">
          <button
            type="button"
            className="btn btn-primary w-full"
            disabled={Boolean(blocker) || busy}
            onClick={() => void onVerify()}
          >
            {busy && <span className="loading loading-spinner loading-sm" />}
            Extract and verify
          </button>
          {blocker && stego && <p className="text-center text-xs text-base-content/60">{blocker}</p>}
        </div>
      </section>

      {/* ---------------- Results ---------------- */}
      <section className="space-y-6">
        {error != null && <ErrorNotice error={error} />}

        {report && (
          <>
            <VerdictBadge verdict={report.verdict} reasons={report.reasons} />
            {source?.expected && (
              <p className="text-xs text-base-content/60">
                {source.expected === report.verdict
                  ? `Matches the expected verdict for ${source.label}.`
                  : `Predicted ${source.expected} for ${source.label}. Some predictions are conditional (see the attack's description); otherwise check the settings.`}
              </p>
            )}
            {report.verdict !== 'Authentic' && HINTS[report.verdict] && (
              <div className="text-sm">
                <h3 className="font-stamp mb-1 text-base">What to check</h3>
                <ul className="list-inside list-disc space-y-1 text-base-content/70">
                  {HINTS[report.verdict]!.map((hint) => (
                    <li key={hint}>{hint}</li>
                  ))}
                </ul>
              </div>
            )}
            <ReportPanel report={report} />
            {report.payload && <PayloadPreview payload={report.payload} />}
          </>
        )}

        {!report && !error && (
          <div className="border-base-300 text-base-content/50 border border-dashed p-6 text-center text-sm">
            The verdict and its evidence will appear here.
          </div>
        )}

        {stego && (
          <div>
            <h3 className="font-stamp mb-2 text-lg">Received file</h3>
            {isAudio ? (
              <audio controls src={stegoUrl ?? undefined} className="w-full" />
            ) : isVideo ? (
              <ReceivedVideo file={stego} />
            ) : (
              <div className="border-base-300 bg-base-200 flex max-h-[32rem] items-center justify-center overflow-hidden rounded-sm border">
                <img
                  src={stegoUrl ?? undefined}
                  alt="received stego object"
                  className="max-h-[32rem] max-w-full object-contain"
                />
              </div>
            )}
          </div>
        )}
      </section>
    </div>
  )
}

/** Browsers cannot play AVI; play its audio track, which carries the payload. */
function ReceivedVideo({ file }: { file: File }) {
  const { url, error } = useAviAudioTrack(file)
  return (
    <div className="space-y-1">
      <p className="text-xs text-base-content/60">AVI audio track (the payload carrier); browsers cannot play AVI video.</p>
      {url ? (
        <audio controls src={url} className="w-full" />
      ) : (
        <p className="text-xs text-base-content/40">{error ? 'could not read the audio track' : 'extracting the audio track…'}</p>
      )}
    </div>
  )
}
