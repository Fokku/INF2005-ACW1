import { useState } from 'react'
import { api } from '../api/client'
import { Exhibit } from '../components/Exhibit'
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
    <div className="grid gap-x-10 gap-y-8 lg:grid-cols-2">
      <section className="space-y-6">
        <div>
          <h2 className="font-stamp text-lg">Generate a demo key pair</h2>
          <p className="mt-2 text-sm text-base-content/70">
            Ed25519. The private key signs the payload; the public key is what a verifier needs.
            These keys exist only for the assignment demo — in a real deployment the private key
            would never leave the signer's machine, let alone be generated in a browser.
          </p>
          <div className="mt-4 space-y-4">
            <Field label="Key label">
              <input
                className="input font-exhibit w-full"
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

        <p className="text-xs tracking-wide text-base-content/60 uppercase">
          Private key never leaves this machine — save it under{' '}
          <code className="font-exhibit normal-case">keys/private/</code>, which is gitignored. Only
          the public key belongs in the repository.
        </p>
      </section>

      <section className="space-y-6">
        {error != null && <ErrorNotice error={error} />}

        {pair && (
          <>
            <div className="space-y-3">
              <h2 className="font-stamp text-lg">Key details</h2>
              <div className="grid gap-3 sm:grid-cols-2">
                <Exhibit label="Algorithm">{pair.key.algorithm}</Exhibit>
                <Exhibit label="Fingerprint">{pair.key.fingerprint}</Exhibit>
              </div>
              <p className="text-xs text-base-content/60">
                Read the fingerprint out to party B. If their copy matches, you are both using the
                same key and a valid signature really does mean what it looks like.
              </p>
              <Exhibit label="Public key (PEM)">
                <pre className="max-h-40 overflow-auto whitespace-pre-wrap">{pair.key.public_key_pem}</pre>
              </Exhibit>
            </div>

            <div className="flex flex-wrap gap-2">
              <a href={pair.public_key_file.download_url} download className="btn btn-primary btn-sm">
                Download public key
              </a>
              <a href={pair.private_key_file.download_url} download className="btn btn-outline btn-sm">
                Download private key
              </a>
            </div>
          </>
        )}

        {!pair && !error && (
          <div className="border-base-300 text-base-content/50 border border-dashed p-6 text-center text-sm">
            Generated keys will appear here.
          </div>
        )}
      </section>
    </div>
  )
}
