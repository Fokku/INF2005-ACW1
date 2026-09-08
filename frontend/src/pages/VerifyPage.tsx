import { useState } from 'react'
import { api } from '../api/client'
import { Field } from '../components/Field'
import { FilePicker } from '../components/FilePicker'
import { LsbSelector } from '../components/LsbSelector'
import { ErrorNotice } from '../components/NotImplemented'
import { PayloadPreview } from '../components/PayloadPreview'
import { ReportPanel } from '../components/ReportPanel'
import { StartLocationPanel } from '../components/StartLocationPanel'
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
    <div className="grid gap-6 lg:grid-cols-2">
      {/* ---------------- Inputs ---------------- */}
      <section className="space-y-4">
        <div className="card bg-base-100 shadow-sm">
          <div className="card-body gap-4">
            <h2 className="card-title text-base">1 · The file you received</h2>
            <FilePicker
              label="Stego image or audio"
              accept=".png,.wav,image/png,audio/wav"
              hint="the file as it arrived"
              file={stego}
              onChange={setStego}
              showHash
            />
            <p className="text-xs opacity-60">
              Compare the SHA-256 above with the one party A read out before sending. If they differ,
              the file changed in transit and the payload is probably gone.
            </p>
            <Field label="Media ID" hint="agreed with the sender">
              <input
                className="input w-full font-mono"
                placeholder={stego?.name ?? 'e.g. Px-x-lena-001'}
                value={mediaId}
                onChange={(e) => setMediaId(e.target.value)}
              />
            </Field>
          </div>
        </div>

        <div className="card bg-base-100 shadow-sm">
          <div className="card-body gap-4">
            <h2 className="card-title text-base">2 · Public key</h2>
            <FilePicker
              label="Public key (PEM)"
              accept=".pem"
              hint="from keys/public/"
              file={publicKeyFile}
              onChange={setPublicKeyFile}
            />
            <div className="divider text-xs">or paste it</div>
            <textarea
              className="textarea h-24 w-full font-mono text-xs"
              placeholder="-----BEGIN PUBLIC KEY-----"
              value={publicKeyText}
              onChange={(e) => setPublicKeyText(e.target.value)}
            />
          </div>
        </div>

        <div className="card bg-base-100 shadow-sm">
          <div className="card-body gap-4">
            <h2 className="card-title text-base">3 · Extraction settings</h2>
            <LsbSelector value={nLsb} onChange={setNLsb} />
            <p className="text-xs opacity-60">
              This must match what party A used. Pick the wrong number and the frame will not parse.
            </p>
            <StartLocationPanel
              mode={startMode}
              onModeChange={setStartMode}
              passphrase={passphrase}
              onPassphraseChange={setPassphrase}
              explicitStart={explicitStart}
              onExplicitStartChange={setExplicitStart}
            />
          </div>
        </div>

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
      <section className="space-y-4">
        {error != null && <ErrorNotice error={error} />}

        {report && (
          <>
            <VerdictBadge verdict={report.verdict} reasons={report.reasons} />
            <ReportPanel report={report} />
            {report.payload && (
              <div className="card bg-base-100 shadow-sm">
                <div className="card-body">
                  <PayloadPreview payload={report.payload} />
                </div>
              </div>
            )}
          </>
        )}

        {stego && (
          <div className="card bg-base-100 shadow-sm">
            <div className="card-body">
              <h3 className="font-medium">Received file</h3>
              {isAudio ? (
                <audio controls src={stegoUrl ?? undefined} className="w-full" />
              ) : (
                <img
                  src={stegoUrl ?? undefined}
                  alt="received stego object"
                  className="max-h-80 rounded-lg border border-base-300 object-contain"
                />
              )}
            </div>
          </div>
        )}

        {!report && !error && (
          <div className="rounded-lg border border-dashed border-base-300 p-6 text-center text-sm opacity-50">
            The verdict and its evidence will appear here.
          </div>
        )}
      </section>
    </div>
  )
}
