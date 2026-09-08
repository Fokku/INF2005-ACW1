import { useEffect, useState } from 'react'
import { api } from '../api/client'
import { Field } from '../components/Field'
import { FilePicker } from '../components/FilePicker'
import { DownloadButton } from '../components/DownloadButton'
import { ErrorNotice } from '../components/NotImplemented'
import { VerdictChip } from '../components/VerdictBadge'
import type { AttackKind, AttackKindInfo, AttackResult } from '../types'

/**
 * Produce the negative test cases on demand.
 *
 * The spec needs at least three negative cases, and an "attack simulation
 * module" is one of the listed optional challenges that can count as the team's
 * innovation. Generating them here makes them reproducible: press a button, get
 * a damaged file, take it to the Verify tab, watch the verdict change.
 *
 * The page is COMPLETE — the attack list already comes from the backend.
 */
export function AttackLabPage() {
  const [kinds, setKinds] = useState<AttackKindInfo[]>([])
  const [stego, setStego] = useState<File | null>(null)
  const [otherCover, setOtherCover] = useState<File | null>(null)
  const [nLsb, setNLsb] = useState(1)
  const [startOffset, setStartOffset] = useState(0)
  const [selected, setSelected] = useState<AttackKind | null>(null)
  const [result, setResult] = useState<AttackResult | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    api.attackKinds().then(setKinds).catch(setError)
  }, [])

  async function onRun(attack: AttackKind) {
    if (!stego) return
    setSelected(attack)
    setBusy(true)
    setError(null)
    setResult(null)
    try {
      setResult(
        await api.runAttack({
          stego,
          attack,
          nLsb,
          startOffset,
          otherCover: otherCover ?? undefined,
        }),
      )
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="alert alert-info items-start text-sm">
        <span className="text-lg leading-none" aria-hidden>
          ℹ
        </span>
        <div>
          <p className="font-medium">This tab manufactures failures on purpose.</p>
          <p className="opacity-80">
            Each attack damages a protected file in a specific way. Take the result to the Verify tab
            and check that the verdict matches the prediction — that is the evidence the negative
            cases actually work.
          </p>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <section className="space-y-4">
          <div className="card bg-base-100 shadow-sm">
            <div className="card-body gap-4">
              <h2 className="card-title text-base">Target</h2>
              <FilePicker
                label="A protected stego file"
                accept=".png,.wav,image/png,audio/wav"
                hint="output from the Protect tab"
                file={stego}
                onChange={setStego}
              />
              <div className="grid grid-cols-2 gap-3">
                <Field label="LSBs used">
                  <input
                    type="number"
                    min={1}
                    max={8}
                    className="input input-sm w-full font-mono"
                    value={nLsb}
                    onChange={(e) => setNLsb(Number(e.target.value))}
                  />
                </Field>
                <Field label="Start offset">
                  <input
                    type="number"
                    min={0}
                    className="input input-sm w-full font-mono"
                    value={startOffset}
                    onChange={(e) => setStartOffset(Number(e.target.value))}
                  />
                </Field>
              </div>
              <FilePicker
                label="Second cover (replay attack only)"
                accept=".png,.wav,image/png,audio/wav"
                hint="where the stolen frame gets transplanted"
                file={otherCover}
                onChange={setOtherCover}
              />
            </div>
          </div>
        </section>

        <section className="space-y-4">
          <div className="card bg-base-100 shadow-sm">
            <div className="card-body gap-3">
              <h2 className="card-title text-base">Attacks</h2>
              {kinds.length === 0 && <p className="text-sm opacity-50">Loading…</p>}
              {kinds.map((kind) => (
                <button
                  key={kind.kind}
                  type="button"
                  disabled={!stego || busy}
                  onClick={() => void onRun(kind.kind)}
                  className={`flex items-start justify-between gap-3 rounded-lg border p-3 text-left transition-colors ${
                    selected === kind.kind
                      ? 'border-primary bg-primary/10'
                      : 'border-base-300 hover:border-primary/50'
                  } disabled:opacity-40`}
                >
                  <div className="min-w-0">
                    <div className="font-mono text-sm">{kind.kind}</div>
                    <div className="text-xs opacity-70">{kind.description}</div>
                  </div>
                  <VerdictChip verdict={kind.expected_verdict} />
                </button>
              ))}
            </div>
          </div>

          {error != null && <ErrorNotice error={error} />}

          {result && (
            <>
              <div className="alert alert-success items-start text-sm">
                <span className="text-lg leading-none" aria-hidden>
                  ✓
                </span>
                <div>
                  <p className="font-medium">Damaged copy created</p>
                  <p className="opacity-80">
                    Verify it and expect <strong>{result.expected_verdict}</strong>.
                  </p>
                </div>
              </div>
              <DownloadButton file={result.output} label="Tampered file" />
            </>
          )}
        </section>
      </div>
    </div>
  )
}
