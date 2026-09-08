import { useState } from 'react'
import { api } from '../api/client'
import { Field } from '../components/Field'
import { ErrorNotice } from '../components/NotImplemented'
import type { KeyPairResult } from '../types'

/**
 * Generate and inspect the signing keys (spec FR4).
 *
 * The page is COMPLETE — it shows a "not implemented" notice until
 * stego_core.signing exists.
 */
export function KeysPage() {
  const [label, setLabel] = useState('team')
  const [pair, setPair] = useState<KeyPairResult | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)

  async function onGenerate() {
    setBusy(true)
    setError(null)
    try {
      setPair(await api.generateKeys(label))
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <section className="space-y-4">
        <div className="card bg-base-100 shadow-sm">
          <div className="card-body gap-4">
            <h2 className="card-title text-base">Generate a demo key pair</h2>
            <p className="text-sm opacity-70">
              Ed25519. The private key signs the payload; the public key is what a verifier needs.
              These keys exist only for the assignment demo — in a real deployment the private key
              would never leave the signer's machine, let alone be generated in a browser.
            </p>
            <Field label="Key label">
              <input
                className="input w-full font-mono"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
              />
            </Field>
            <button
              type="button"
              className="btn btn-primary"
              disabled={busy}
              onClick={() => void onGenerate()}
            >
              {busy && <span className="loading loading-spinner loading-sm" />}
              Generate key pair
            </button>
          </div>
        </div>

        <div className="alert alert-warning items-start text-sm">
          <span className="text-lg leading-none" aria-hidden>
            ⚠
          </span>
          <div>
            <p className="font-medium">Never commit a private key.</p>
            <p className="opacity-80">
              Save it under <code>keys/private/</code>, which is gitignored. Only the public key
              belongs in the repository, and only that is submitted.
            </p>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        {error != null && <ErrorNotice error={error} />}

        {pair && (
          <>
            <div className="card bg-base-100 shadow-sm">
              <div className="card-body gap-3">
                <h2 className="card-title text-base">Key details</h2>
                <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
                  <dt className="opacity-60">Algorithm</dt>
                  <dd className="font-mono">{pair.key.algorithm}</dd>
                  <dt className="opacity-60">Fingerprint</dt>
                  <dd className="font-mono break-all">{pair.key.fingerprint}</dd>
                </dl>
                <p className="text-xs opacity-60">
                  Read the fingerprint out to party B. If their copy matches, you are both using the
                  same key and a valid signature really does mean what it looks like.
                </p>
                <pre className="max-h-40 overflow-auto rounded-lg border border-base-300 bg-base-200 p-3 text-xs">
                  {pair.key.public_key_pem}
                </pre>
              </div>
            </div>

            <div className="flex flex-wrap gap-2">
              <a href={pair.public_key_file.download_url} download className="btn btn-success btn-sm">
                Download public key
              </a>
              <a href={pair.private_key_file.download_url} download className="btn btn-warning btn-sm">
                Download private key
              </a>
            </div>
          </>
        )}

        {!pair && !error && (
          <div className="rounded-lg border border-dashed border-base-300 p-6 text-center text-sm opacity-50">
            Generated keys will appear here.
          </div>
        )}
      </section>
    </div>
  )
}
