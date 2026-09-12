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

const TABS: { id: Tab; num: string; label: string; blurb: string }[] = [
  { id: 'protect', num: '01', label: 'Protect', blurb: 'Party A · embed and sign' },
  { id: 'verify', num: '02', label: 'Verify', blurb: 'Party B · extract and judge' },
  { id: 'keys', num: '03', label: 'Keys', blurb: 'Generate and inspect signing keys' },
  { id: 'attack', num: '04', label: 'Attack Lab', blurb: 'Manufacture the negative cases' },
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
    <div className="min-h-screen bg-base-100 text-base-content">
      <header className="border-b border-base-300 bg-base-100">
        <div className="mx-auto max-w-[72rem] px-6 py-5">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h1 className="font-stamp text-2xl leading-none">Stego / Case File</h1>
              <p className="mt-1.5 text-sm text-base-content/60">
                INF2005 ACW1 · LSB steganography, SHA-256 hashing and Ed25519 signatures
              </p>
            </div>
            <div className="flex items-center gap-2 text-xs text-base-content/60">
              <span
                className={`inline-block size-2 rounded-full ${
                  online === null ? 'bg-base-300' : online ? 'bg-success' : 'bg-error'
                }`}
              />
              <span>{online === null ? 'checking API…' : online ? 'API connected' : 'API unreachable'}</span>
            </div>
          </div>

          <nav role="tablist" className="mt-5 flex flex-wrap gap-x-8 gap-y-2">
            {TABS.map((t) => (
              <button
                key={t.id}
                role="tab"
                type="button"
                aria-selected={tab === t.id}
                onClick={() => setTab(t.id)}
                className={`font-stamp border-b-2 pb-2 text-base transition-colors ${
                  tab === t.id
                    ? 'border-primary text-base-content'
                    : 'border-transparent text-base-content/50 hover:text-base-content/80'
                }`}
              >
                <span className="text-base-content/40">{t.num}</span> {t.label}
              </button>
            ))}
          </nav>
        </div>
      </header>

      <main className="mx-auto max-w-[72rem] px-6 py-8">
        <p className="mb-6 text-sm text-base-content/60">{active.blurb}</p>

        {online === false && (
          <div className="alert alert-error mb-6 items-start">
            <span className="text-xl leading-none" aria-hidden>
              ✗
            </span>
            <div>
              <h3 className="font-medium">The backend is not running</h3>
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

      <footer className="border-t border-base-300 py-6 text-center text-xs text-base-content/50">
        Built for INF2005 ACW1 · see TODO.md for what still needs implementing
      </footer>
    </div>
  )
}
