import { useEffect, useState } from 'react'
import { api } from './api/client'
import { AttackLabPage } from './pages/AttackLabPage'
import { KeysPage } from './pages/KeysPage'
import { ProtectPage } from './pages/ProtectPage'
import { VerifyPage } from './pages/VerifyPage'

/**
 * Application shell: four tabs held in React state.
 *
 * No router on purpose — four screens with no deep linking do not need one.
 *
 * Complete — no TODO.
 */

type Tab = 'protect' | 'verify' | 'keys' | 'attack'

const TABS: { id: Tab; label: string; blurb: string }[] = [
  { id: 'protect', label: 'Protect', blurb: 'Party A · embed and sign' },
  { id: 'verify', label: 'Verify', blurb: 'Party B · extract and judge' },
  { id: 'keys', label: 'Keys', blurb: 'Generate and inspect signing keys' },
  { id: 'attack', label: 'Attack Lab', blurb: 'Manufacture the negative cases' },
]

export default function App() {
  const [tab, setTab] = useState<Tab>('protect')
  const [online, setOnline] = useState<boolean | null>(null)

  useEffect(() => {
    api
      .health()
      .then(() => setOnline(true))
      .catch(() => setOnline(false))
  }, [])

  const active = TABS.find((t) => t.id === tab)!

  return (
    <div className="min-h-screen bg-base-200">
      <header className="border-b border-base-300 bg-base-100">
        <div className="mx-auto max-w-7xl px-4 py-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h1 className="text-xl font-bold">Steganographic Integrity Verification</h1>
              <p className="text-sm opacity-60">
                INF2005 ACW1 · LSB steganography, SHA-256 hashing and Ed25519 signatures
              </p>
            </div>
            <div className="flex items-center gap-2 text-xs">
              <span
                className={`inline-block size-2 rounded-full ${
                  online === null ? 'bg-base-300' : online ? 'bg-success' : 'bg-error'
                }`}
              />
              <span className="opacity-60">
                {online === null ? 'checking API…' : online ? 'API connected' : 'API unreachable'}
              </span>
            </div>
          </div>

          <div role="tablist" className="tabs tabs-box mt-4">
            {TABS.map((t) => (
              <button
                key={t.id}
                role="tab"
                type="button"
                className={`tab ${tab === t.id ? 'tab-active' : ''}`}
                onClick={() => setTab(t.id)}
              >
                {t.label}
              </button>
            ))}
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-4 py-6">
        <p className="mb-4 text-sm opacity-60">{active.blurb}</p>

        {online === false && (
          <div className="alert alert-error mb-4 items-start">
            <span className="text-xl leading-none" aria-hidden>
              ✗
            </span>
            <div>
              <h3 className="font-bold">The backend is not running</h3>
              <p className="text-sm">
                Start it with <code>stego serve --reload</code> from an activated virtualenv, then
                reload this page.
              </p>
            </div>
          </div>
        )}

        {tab === 'protect' && <ProtectPage />}
        {tab === 'verify' && <VerifyPage />}
        {tab === 'keys' && <KeysPage />}
        {tab === 'attack' && <AttackLabPage />}
      </main>

      <footer className="border-t border-base-300 py-6 text-center text-xs opacity-50">
        Built for INF2005 ACW1 · see TODO.md for what still needs implementing
      </footer>
    </div>
  )
}
