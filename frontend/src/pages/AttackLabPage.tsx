import { useEffect, useState } from 'react'
import { api, fetchAsFile } from '../api/client'
import { Field } from '../components/Field'
import { FilePicker } from '../components/FilePicker'
import { DownloadButton } from '../components/DownloadButton'
import { ErrorNotice } from '../components/NotImplemented'
import { StepSection } from '../components/StepSection'
import { VerdictChip } from '../components/VerdictBadge'
import type {
  AttackKind,
  AttackKindInfo,
  AttackPrefill,
  AttackResult,
  ProtectHandoff,
  PublicKeyFile,
  SampleCase,
  Verdict,
  VerifyPrefill,
} from '../types'

/**
 * Produce the negative test cases on demand.
 *
 * The spec needs at least three negative cases, and an "attack simulation
 * module" is one of the listed optional challenges that can count as the team's
 * innovation. Generating them here makes them reproducible: press a button, get
 * a damaged file, send it to the Verify tab with the original settings, watch
 * the verdict change.
 *
 * Attack descriptions and conditional verdict predictions come from the backend.
 */

/** Where the target came from, and what Verify needs to check it afterwards. */
interface TargetContext {
  source: string
  mediaId: string
  redundancy: number
  /** The target's frame is sealed: Verify cannot even find it without the passphrase. */
  sealed?: boolean
  /** The hidden message is encrypted: Verify needs the passphrase to show it (not for the verdict). */
  messageEncrypted?: boolean
  /** Only for demo samples, whose passphrase is published with them; Protect's never travels. */
  passphrase?: string | null
  publicKeyPem?: string | null
  publicKeyLabel?: string | null
}

export function AttackLabPage({
  prefill,
  handoff,
  onVerify,
}: {
  prefill: AttackPrefill | null
  handoff: ProtectHandoff | null
  onVerify: (prefill: Omit<VerifyPrefill, 'id'>) => void
}) {
  const [kinds, setKinds] = useState<AttackKindInfo[]>([])
  const [samples, setSamples] = useState<SampleCase[]>([])
  const [publicKeys, setPublicKeys] = useState<PublicKeyFile[]>([])
  const [stego, setStego] = useState<File | null>(null)
  const [context, setContext] = useState<TargetContext | null>(null)
  const [otherCover, setOtherCover] = useState<File | null>(null)
  const [nLsb, setNLsb] = useState(1)
  const [startOffset, setStartOffset] = useState(0)
  const [redundancy, setRedundancy] = useState(1)
  const [sealed, setSealed] = useState(false)
  const [selected, setSelected] = useState<AttackKind | null>(null)
  const [result, setResult] = useState<AttackResult | null>(null)
  // The settings the current result was produced with (the form may change
  // afterwards): the prediction and the Verify hand-off must describe this file.
  const [ran, setRan] = useState<{ nLsb: number; startOffset: number; redundancy: number; sealed: boolean } | null>(
    null,
  )
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    api.attackKinds().then(setKinds).catch(setError)
    api.samples().then(setSamples).catch(() => setSamples([]))
    api.publicKeys().then(setPublicKeys).catch(() => setPublicKeys([]))
  }, [])

  function applyTarget(file: File, lsb: number, offset: number, ctx: TargetContext) {
    setStego(file)
    setNLsb(lsb)
    setStartOffset(offset)
    setRedundancy(ctx.redundancy)
    setSealed(Boolean(ctx.sealed))
    setContext(ctx)
    setSelected(null)
    setResult(null)
    setError(null)
  }

  // Apply a hand-off once per id, while rendering (React's "adjust state when a
  // prop changes" pattern) rather than in an effect.
  const [appliedPrefill, setAppliedPrefill] = useState<number | null>(null)
  if (prefill && prefill.id !== appliedPrefill) {
    setAppliedPrefill(prefill.id)
    applyTarget(prefill.file, prefill.nLsb, prefill.startOffset, {
      source: prefill.source,
      mediaId: prefill.mediaId,
      redundancy: prefill.redundancy,
      sealed: prefill.sealed,
      messageEncrypted: prefill.messageEncrypted,
      publicKeyPem: prefill.publicKeyPem,
      publicKeyLabel: prefill.publicKeyLabel,
    })
  }

  async function takeProtected() {
    if (!handoff) return
    try {
      const { result: r } = handoff
      const file = await fetchAsFile(r.stego.url, r.stego.filename, r.stego.mime)
      applyTarget(file, r.n_lsb, r.start_offset, {
        source: 'Protect tab',
        mediaId: handoff.mediaId,
        redundancy: r.redundancy,
        sealed: r.sealed,
        messageEncrypted: r.payload.message_encrypted,
        publicKeyPem: r.signer_public_key_pem,
        publicKeyLabel: `signer key ${r.signer_fingerprint.slice(0, 12)}…`,
      })
    } catch (err) {
      setError(err)
    }
  }

  // Only protected samples with a known explicit offset make sensible targets.
  const targets = samples.filter((s) => s.expected_verdict === 'Authentic' && s.explicit_start !== null)

  async function takeSample(id: string) {
    const sample = targets.find((s) => s.id === id)
    if (!sample) return
    try {
      const file = await fetchAsFile(sample.url, sample.file.split('/').pop() ?? sample.id)
      const key = publicKeys.find((k) => k.name === sample.public_key)
      applyTarget(file, sample.n_lsb, sample.explicit_start ?? 0, {
        source: `Sample · ${sample.file}`,
        mediaId: sample.media_id,
        redundancy: sample.redundancy,
        passphrase: sample.passphrase,
        publicKeyPem: key?.public_key_pem,
        publicKeyLabel: key ? `keys/public/${key.name}` : null,
      })
    } catch (err) {
      setError(err)
    }
  }

  async function onRun(attack: AttackKind) {
    if (!stego) return
    setSelected(attack)
    setBusy(true)
    setError(null)
    setResult(null)
    setRan({ nLsb, startOffset, redundancy, sealed })
    try {
      setResult(
        await api.runAttack({
          stego,
          attack,
          nLsb,
          startOffset,
          otherCover: otherCover ?? undefined,
          sealed,
          // corrupt_payload and replay must reach every copy: damaging one of
          // three is outvoted, and replay has to move all of them.
          redundancy,
        }),
      )
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }

  // The backend's prediction for lsb_noise assumes a single copy; with robust
  // embedding (3 or 5 copies) the majority vote repairs the damage. The other
  // attacks are told the copy count, so their predictions already hold.
  const ranCopies = ran?.redundancy ?? 1
  const predicted: Verdict | null = result
    ? result.attack === 'lsb_noise' && ranCopies > 1
      ? 'Authentic'
      : result.expected_verdict
    : null

  async function verifyResult() {
    if (!result || !ran) return
    try {
      const file = await fetchAsFile(result.output.url, result.output.filename, result.output.mime)
      const passphrase = context?.passphrase || null
      // Explicit mode skips the passphrase-derived start, but a sealed frame is
      // still invisible without the passphrase: Verify would report Payload
      // Missing (or Cannot Verify) instead of the predicted verdict.
      const passphraseNote = passphrase
        ? null
        : ran.sealed
          ? 'Type the shared passphrase: the frame is sealed, and a sealed frame cannot be found without it.'
          : context?.messageEncrypted
            ? 'Type the shared passphrase to read the encrypted message (the verdict does not need it).'
            : null
      const settingsNote = context
        ? 'Original media ID, LSB count, copies and start offset carried over. The prediction assumes these settings.'
        : 'Enter the original media ID and public key before verifying.'
      onVerify({
        source: `Attack Lab · ${result.attack}`,
        file,
        mediaId: context?.mediaId ?? '',
        nLsb: ran.nLsb,
        redundancy: ran.redundancy,
        // Explicit mode with the original offset: after a crop or replay the
        // cover size changes, and a derived start would move with it.
        startMode: 'explicit',
        explicitStart: ran.startOffset,
        passphrase,
        requiresPassphrase: ran.sealed,
        publicKeyPem: context?.publicKeyPem ?? null,
        publicKeyLabel: context?.publicKeyLabel ?? null,
        expectedVerdict: predicted,
        note: passphraseNote ? `${passphraseNote} ${settingsNote}` : settingsNote,
      })
    } catch (err) {
      setError(err)
    }
  }

  return (
    <div className="space-y-8">
      <p className="max-w-prose text-sm text-base-content/70">
        <span className="text-base-content font-medium">This tab manufactures failures on purpose.</span>{' '}
        Each attack damages a protected file in a specific way. Send the result to the Verify tab and
        check that the verdict matches the prediction — that is the evidence the negative cases
        actually work. Predictions assume the original settings; cropping and re-encoding may produce
        a different failure if the embedded frame is lost. A large file may report Cannot Verify when
        the payload search reaches its limit.
      </p>

      <div className="grid gap-x-10 gap-y-8 lg:grid-cols-2">
        <StepSection num="A" title="Target">
          <div className="flex flex-wrap gap-2">
            {handoff && (
              <button type="button" className="btn btn-outline btn-sm" onClick={() => void takeProtected()}>
                Use {handoff.result.stego.filename} from Protect
              </button>
            )}
            {targets.length > 0 && (
              <select
                aria-label="Use a demo sample as the target"
                className="select select-sm min-w-0 flex-1"
                value=""
                onChange={(e) => void takeSample(e.target.value)}
              >
                <option value="" disabled>
                  Or use a protected demo sample…
                </option>
                {targets.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.file.split('/').pop()} ({s.n_lsb} LSB, start {s.explicit_start})
                  </option>
                ))}
              </select>
            )}
          </div>
          {context && (
            <div className="border-primary/60 bg-primary/10 rounded-sm border px-3 py-2 text-sm">
              Target from <span className="font-medium">{context.source}</span> · media ID{' '}
              <span className="font-exhibit text-xs">{context.mediaId}</span>
            </div>
          )}
          <FilePicker
            label="A protected stego file"
            accept=".png,.wav,.avi"
            hint="Output from Protect. AVI supports all attacks except crop."
            file={stego}
            onChange={(f) => {
              setStego(f)
              setContext(null)
              setResult(null)
            }}
          />
          <div className="grid grid-cols-3 gap-3">
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
            <Field label="Copies">
              <select
                aria-label="Copies embedded"
                className="select select-sm font-exhibit w-full"
                value={redundancy}
                onChange={(e) => setRedundancy(Number(e.target.value))}
              >
                {[1, 3, 5].map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </select>
            </Field>
          </div>
          <label className="flex cursor-pointer items-center gap-2 text-sm">
            <input
              type="checkbox"
              className="checkbox checkbox-sm checkbox-primary"
              checked={sealed}
              onChange={(e) => setSealed(e.target.checked)}
            />
            <span>Target has a sealed frame</span>
          </label>
          <p className="text-xs text-base-content/70">
            All three come from the Protect report (filled in automatically when the target comes from
            Protect or a sample). Verification of the damaged file uses the original media ID, public
            key and this offset in explicit start mode. A sealed frame's header is encrypted, so
            corrupt_payload and replay then work blind from the offset instead of reading the header,
            and Verify needs the shared passphrase to find the frame at all.
          </p>
          <FilePicker
            label="Second cover (replay attack only)"
            accept=".png,.wav,.avi"
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
                  disabled={!stego || busy || (kind.kind === 'replay' && !otherCover)}
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
            {!stego && kinds.length > 0 && (
              <p className="mt-3 text-xs text-base-content/60">Choose a target file to enable the attacks.</p>
            )}
          </div>

          {error != null && <ErrorNotice error={error} />}

          {result && (
            <>
              <div className="border-base-300 space-y-3 rounded-sm border p-4 text-sm">
                <p className="font-medium">Damaged copy created: {result.attack}</p>
                <p className="flex flex-wrap items-center gap-2 text-base-content/70">
                  Predicted verdict: <VerdictChip verdict={predicted ?? result.expected_verdict} />
                  {result.attack === 'lsb_noise' && ranCopies > 1 && (
                    <span className="text-xs">({ranCopies} copies embedded: the majority vote repairs the noise)</span>
                  )}
                </p>
                <p className="text-base-content/70">{result.description}</p>
                <button type="button" className="btn btn-primary btn-sm" onClick={() => void verifyResult()}>
                  Verify the damaged file →
                </button>
              </div>
              <DownloadButton file={result.output} label="Damaged file" tone="damaged" />
            </>
          )}
        </section>
      </div>
    </div>
  )
}
