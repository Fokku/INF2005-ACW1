import { useEffect, useState } from 'react'
import { api } from '../api/client'
import { Field } from '../components/Field'
import { FilePicker } from '../components/FilePicker'
import { DownloadButton } from '../components/DownloadButton'
import { ErrorNotice } from '../components/NotImplemented'
import { StepSection } from '../components/StepSection'
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
    <div className="space-y-8">
      <p className="max-w-prose text-sm text-base-content/70">
        <span className="text-base-content font-medium">This tab manufactures failures on purpose.</span>{' '}
        Each attack damages a protected file in a specific way. Take the result to the Verify tab
        and check that the verdict matches the prediction — that is the evidence the negative cases
        actually work.
      </p>

      <div className="grid gap-x-10 gap-y-8 lg:grid-cols-2">
        <StepSection num="A" title="Target">
          <FilePicker
            label="A protected stego file"
            accept=".png,.wav"
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
                className="input input-sm font-exhibit w-full"
                value={nLsb}
                onChange={(e) => setNLsb(Number(e.target.value))}
              />
            </Field>
            <Field label="Start offset">
              <input
                type="number"
                min={0}
                className="input input-sm font-exhibit w-full"
                value={startOffset}
                onChange={(e) => setStartOffset(Number(e.target.value))}
              />
            </Field>
          </div>
          <FilePicker
            label="Second cover (replay attack only)"
            accept=".png,.wav"
            hint="where the stolen frame gets transplanted"
            file={otherCover}
            onChange={setOtherCover}
          />
        </StepSection>

        <section className="space-y-6">
          <div>
            <h2 className="font-stamp mb-3 text-lg">Attacks</h2>
            {kinds.length === 0 && <p className="text-sm text-base-content/50">Loading…</p>}
            <div className="grid gap-3 sm:grid-cols-2">
              {kinds.map((kind) => (
                <button
                  key={kind.kind}
                  type="button"
                  disabled={!stego || busy}
                  onClick={() => void onRun(kind.kind)}
                  className={`flex flex-col items-start gap-2 rounded-sm border p-3 text-left transition-colors ${
                    selected === kind.kind
                      ? 'border-primary bg-primary/10'
                      : 'border-base-300 hover:border-primary/50'
                  } disabled:opacity-40`}
                >
                  <div className="min-w-0">
                    <div className="font-exhibit text-sm">{kind.kind}</div>
                    <div className="mt-0.5 text-xs text-base-content/70">{kind.description}</div>
                  </div>
                  <VerdictChip verdict={kind.expected_verdict} />
                </button>
              ))}
            </div>
          </div>

          {error != null && <ErrorNotice error={error} />}

          {result && (
            <>
              <div className="border-verdict-authentic bg-verdict-authentic/10 rounded-sm border p-4 text-sm">
                <p className="font-medium">Damaged copy created</p>
                <p className="mt-1 text-base-content/70">
                  Verify it and expect <strong className="text-base-content">{result.expected_verdict}</strong>.
                </p>
              </div>
              <DownloadButton file={result.output} label="Tampered file" />
            </>
          )}
        </section>
      </div>
    </div>
  )
}
