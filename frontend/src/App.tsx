import { useEffect, useState } from 'react'
import { api } from './api/client'
import { AttackLabPage } from './pages/AttackLabPage'
import { KeysPage } from './pages/KeysPage'
import { ProtectPage } from './pages/ProtectPage'
import { SteganalysisPage } from './pages/SteganalysisPage'
import { VerifyPage } from './pages/VerifyPage'
import type { AttackPrefill, ProtectHandoff, VerifyPrefill } from './types'

/**
 * Application shell: five tabs held in React state.
 *
 * No router on purpose — five screens with no deep linking do not need one.
 * Every page stays mounted and inactive ones are hidden, so switching tabs
 * mid-demo never throws away a result. The shell also carries hand-offs
 * between tabs: Protect → Verify / Attack Lab, and Attack Lab → Verify.
 */

type Tab = 'protect' | 'verify' | 'keys' | 'attack' | 'steganalysis'

const TABS: { id: Tab; num: string; label: string; blurb: string }[] = [
  { id: 'protect', num: '01', label: 'Protect', blurb: 'Party A · embed and sign' },
  { id: 'verify', num: '02', label: 'Verify', blurb: 'Party B · extract and judge' },
  { id: 'keys', num: '03', label: 'Keys', blurb: 'Generate and inspect signing keys' },
  { id: 'attack', num: '04', label: 'Attack Lab', blurb: 'Manufacture the negative cases' },
  { id: 'steganalysis', num: '05', label: 'Steganalysis', blurb: 'Detect LSB embedding without any key' },
]

export default function App() {
  const [tab, setTab] = useState<Tab>('protect')
  const [online, setOnline] = useState<boolean | null>(null)
  const [handoff, setHandoff] = useState<ProtectHandoff | null>(null)
  const [verifyPrefill, setVerifyPrefill] = useState<VerifyPrefill | null>(null)
  const [attackPrefill, setAttackPrefill] = useState<AttackPrefill | null>(null)

  useEffect(() => {
    api
      .health()
      .then(() => setOnline(true))
      .catch(() => setOnline(false))
  }, [])

  function sendToVerify(prefill: Omit<VerifyPrefill, 'id'>) {
    setVerifyPrefill({ ...prefill, id: Date.now() })
    setTab('verify')
  }

  function sendToAttack(prefill: Omit<AttackPrefill, 'id'>) {
    setAttackPrefill({ ...prefill, id: Date.now() })
    setTab('attack')
  }

  const active = TABS.find((t) => t.id === tab)!

  return (
    <div className="min-h-screen bg-base-100 text-base-content">
      <header className="border-b border-base-300 bg-base-100">
        <div className="mx-auto max-w-[72rem] px-6 py-5">
          <div>
            <h1 className="font-stamp text-3xl leading-none">Stego / Case File</h1>
            <p className="mt-1.5 text-sm text-base-content/60">
              INF2005 ACW1 · LSB steganography, SHA-256 hashing and Ed25519 signatures
            </p>
          </div>

          <nav role="tablist" className="mt-5 flex flex-wrap gap-x-8 gap-y-2">
            {TABS.map((t) => (
              <button
                key={t.id}
                role="tab"
                type="button"
                aria-selected={tab === t.id}
                aria-controls={`panel-${t.id}`}
                onClick={() => setTab(t.id)}
                className={`font-stamp border-b-2 pb-2 text-lg transition-colors ${
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
                Start it from the repository root with <code>scripts/demo.sh</code> (Windows:{' '}
                <code>scripts\demo.ps1</code>), then reload this page.
              </p>
            </div>
          </div>
        )}

        <div role="tabpanel" id="panel-protect" hidden={tab !== 'protect'}>
          <ProtectPage
            onProtected={setHandoff}
            onVerify={sendToVerify}
            onAttack={sendToAttack}
          />
        </div>
        <div role="tabpanel" id="panel-verify" hidden={tab !== 'verify'}>
          <VerifyPage prefill={verifyPrefill} />
        </div>
        <div role="tabpanel" id="panel-keys" hidden={tab !== 'keys'}>
          <KeysPage />
        </div>
        <div role="tabpanel" id="panel-attack" hidden={tab !== 'attack'}>
          <AttackLabPage prefill={attackPrefill} handoff={handoff} onVerify={sendToVerify} />
        </div>
        <div role="tabpanel" id="panel-steganalysis" hidden={tab !== 'steganalysis'}>
          <SteganalysisPage />
        </div>
      </main>
    </div>
  )
}
