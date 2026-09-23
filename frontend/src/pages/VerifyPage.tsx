import { useState } from 'react'
import { api } from '../api/client'
import { Field } from '../components/Field'
import { FilePicker } from '../components/FilePicker'
import { LsbSelector } from '../components/LsbSelector'
import { ErrorNotice } from '../components/NotImplemented'
import { PayloadPreview } from '../components/PayloadPreview'
import { ReportPanel } from '../components/ReportPanel'
import { StartLocationPanel } from '../components/StartLocationPanel'
import { StepSection } from '../components/StepSection'
import { VerdictBadge } from '../components/VerdictBadge'
import type { StartMode, VerifyReport } from '../types'

/**
 * Party B: check a received file and say whether it is authentic.
 *
 * Covers steps 7 to 10 of the required security workflow.
 *
 * The page is COMPLETE — it shows a "not implemented" notice until the backend
 * core exists.
 */
export function VerifyPage() {
  const [stego, setStego] = useState<File | null>(null)
  const [publicKeyFile, setPublicKeyFile] = useState<File | null>(null)
  const [publicKeyText, setPublicKeyText] = useState('')
  const [nLsb, setNLsb] = useState(1)
  const [mediaId, setMediaId] = useState('')
  const [startMode, setStartMode] = useState<StartMode>('derived')
  const [passphrase, setPassphrase] = useState('')
  const [explicitStart, setExplicitStart] = useState(1024)

  const [report, setReport] = useState<VerifyReport | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)

  const stegoUrl = stego ? URL.createObjectURL(stego) : null
  const isAudio = stego?.name.toLowerCase().endsWith('.wav') ?? false
  const isVideo = stego?.name.toLowerCase().endsWith('.avi') ?? false

  async function onVerify() {
    if (!stego) return
    setBusy(true)
    setError(null)
    setReport(null)
    try {
      setReport(
        await api.verify({
          stego,
          publicKeyFile: publicKeyFile ?? undefined,
          publicKeyText: publicKeyText || undefined,
          nLsb,
          mediaId: mediaId || stego.name,
          startMode,
          explicitStart: startMode === 'explicit' ? explicitStart : undefined,
          passphrase: passphrase || undefined,
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
        <StepSection num="1" title="The file you received">
          <FilePicker
            label="Stego image, audio, or video"
            accept=".png,.wav,.avi"
            hint="the file as it arrived"
            file={stego}
            onChange={(f) => {
              setStego(f)
              if (f && !mediaId) setMediaId(f.name)
            }}
            showHash
          />
          <p className="text-xs text-base-content/60">
            Compare the SHA-256 above with the one party A read out before sending. If they differ,
            the file changed in transit and the payload is probably gone.
          </p>
          <Field label="Media ID" hint="agreed with the sender">
            <input
              className="input font-exhibit w-full"
              placeholder={stego?.name ?? 'e.g. Px-x-lena-001'}
              value={mediaId}
              onChange={(e) => setMediaId(e.target.value)}
            />
          </Field>
        </StepSection>

        <StepSection num="2" title="Public key">
          <FilePicker
            label="Public key (PEM)"
            accept=".pem"
            hint="from keys/public/"
            file={publicKeyFile}
            onChange={setPublicKeyFile}
          />
          <div className="divider text-xs">or paste it</div>
          <textarea
            className="textarea font-exhibit h-24 w-full text-xs"
            placeholder="-----BEGIN PUBLIC KEY-----"
            value={publicKeyText}
            onChange={(e) => setPublicKeyText(e.target.value)}
          />
        </StepSection>

        <StepSection num="3" title="Extraction settings">
          <LsbSelector value={nLsb} onChange={setNLsb} />
          <p className="text-xs text-base-content/60">
            This must match what party A used. Pick the wrong number and the frame will not parse.
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

        <button
          type="button"
          className="btn btn-primary w-full"
          disabled={!stego || busy}
          onClick={() => void onVerify()}
        >
          {busy && <span className="loading loading-spinner loading-sm" />}
          Extract and verify
        </button>
      </section>

      {/* ---------------- Results ---------------- */}
      <section className="space-y-6">
        {error != null && <ErrorNotice error={error} />}

        {report && (
          <>
            <VerdictBadge verdict={report.verdict} reasons={report.reasons} />
            <ReportPanel report={report} />
            {report.payload && <PayloadPreview payload={report.payload} />}
          </>
        )}

        {stego && (
          <div>
            <h3 className="font-stamp mb-2 text-lg">Received file</h3>
            {isAudio ? (
              <audio controls src={stegoUrl ?? undefined} className="w-full" />
            ) : isVideo ? (
              <video controls src={stegoUrl ?? undefined} className="w-full rounded-sm" />
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

        {!report && !error && (
          <div className="border-base-300 text-base-content/50 border border-dashed p-6 text-center text-sm">
            The verdict and its evidence will appear here.
          </div>
        )}
      </section>
    </div>
  )
}
