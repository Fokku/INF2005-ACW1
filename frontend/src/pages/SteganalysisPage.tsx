import { useEffect, useMemo, useState } from 'react'
import { api, fetchAsFile } from '../api/client'
import { EvidenceStrip } from '../components/EvidenceStrip'
import { Exhibit } from '../components/Exhibit'
import { Field } from '../components/Field'
import { FilePicker } from '../components/FilePicker'
import { ErrorNotice } from '../components/NotImplemented'
import { StepSection } from '../components/StepSection'
import { formatP } from '../lib/format'
import type { SampleCase, SteganalysisReport } from '../types'

/**
 * Steganalysis (optional challenge, spec Section 8): judge a file WITHOUT any
 * key, passphrase or settings — the attacker's view of our own stego objects.
 *
 * The method (Ke Ying's, backend/stego_core/steganalysis.py) combines the
 * Westfeld–Pfitzmann chi-square pairs-of-values test with a byte-phase test
 * that spots the period-8/n_lsb pattern byte-oriented hidden data leaves.
 */

/** stego_core.steganalysis.PHASE_ALPHA: a window is flagged below this p-value. */
const PHASE_THRESHOLD = 1e-6
const WINDOWS = [1024, 4096, 16384]

export function SteganalysisPage() {
  const [file, setFile] = useState<File | null>(null)
  const [windowSize, setWindowSize] = useState(4096)
  const [samples, setSamples] = useState<SampleCase[]>([])
  const [report, setReport] = useState<SteganalysisReport | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    api.samples().then(setSamples).catch(() => setSamples([]))
  }, [])

  // One entry per distinct sample file (several cases reuse the same file).
  const sampleFiles = useMemo(() => {
    const seen = new Map<string, SampleCase>()
    for (const s of samples) if (!seen.has(s.file)) seen.set(s.file, s)
    return [...seen.values()]
  }, [samples])

  async function analyse(target: File | null = file) {
    if (!target) return
    setBusy(true)
    setError(null)
    setReport(null)
    try {
      setReport(await api.steganalysis({ file: target, window: windowSize }))
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }

  async function loadSample(path: string) {
    const sample = sampleFiles.find((s) => s.file === path)
    if (!sample) return
    try {
      const next = await fetchAsFile(sample.url, sample.file.split('/').pop() ?? sample.id)
      setFile(next)
      await analyse(next)
    } catch (err) {
      setError(err)
    }
  }

  const flaggedWindows = report?.windows.filter((w) => w.flagged) ?? []

  return (
    <div className="grid gap-x-10 gap-y-8 lg:grid-cols-2">
      <section className="space-y-8">
        <p className="max-w-prose text-sm text-base-content/70">
          <span className="text-base-content font-medium">No key, no passphrase, no settings.</span>{' '}
          This is what an analyst sees: can they tell a file carries hidden data, and where? It is the
          honest counterpart to the start-location design — a secret offset hides where to read, not
          that something was written.
        </p>

        <StepSection num="1" title="File to analyse">
          {sampleFiles.length > 0 && (
            <Field label="Analyse a demo sample" hint="samples/">
              <select
                aria-label="Analyse a demo sample"
                className="select w-full"
                value=""
                onChange={(e) => void loadSample(e.target.value)}
              >
                <option value="" disabled>
                  Choose a sample file…
                </option>
                {sampleFiles.map((s) => (
                  <option key={s.file} value={s.file}>
                    {s.file.replace(/^samples\//, '')}
                  </option>
                ))}
              </select>
            </Field>
          )}
          <FilePicker
            label="Image, audio, or video"
            accept=".png,.wav,.avi"
            hint="any file, protected or not"
            file={file}
            onChange={(f) => {
              setFile(f)
              setReport(null)
            }}
          />
          <Field label="Window size" hint="elements per window">
            <div className="join flex">
              {WINDOWS.map((w) => (
                <button
                  key={w}
                  type="button"
                  aria-pressed={windowSize === w}
                  onClick={() => setWindowSize(w)}
                  className={`btn btn-sm join-item flex-1 ${windowSize === w ? 'btn-primary' : 'btn-outline'}`}
                >
                  {w.toLocaleString()}
                </button>
              ))}
            </div>
          </Field>
          <button
            type="button"
            className="btn btn-primary w-full"
            disabled={!file || busy}
            onClick={() => void analyse()}
          >
            {busy && <span className="loading loading-spinner loading-sm" />}
            Analyse
          </button>
        </StepSection>

        <StepSection num="2" title="Method">
          <p className="text-sm text-base-content/70">
            {report?.method ??
              'Chi-square pairs of values: LSB replacement with random-looking bits evens out the counts of each value pair (2k, 2k+1). Byte phase: hidden bytes repeat with a period of 8 / n_lsb elements, which biases some phases. Each window of the file is tested separately, which also reveals where the payload sits.'}
          </p>
          <p className="text-xs text-base-content/60">
            Method and CLI by Ke Ying (<code className="font-exhibit">scripts/steganalysis.py</code>).
          </p>
        </StepSection>
      </section>

      <section className="space-y-6">
        {error != null && <ErrorNotice error={error} />}

        {report && (
          <>
            <div
              className={`rounded-sm border p-5 ${
                report.suspicious
                  ? 'border-verdict-missing bg-verdict-missing/15'
                  : 'border-verdict-unknown bg-verdict-unknown/15'
              }`}
            >
              <div className="flex items-baseline gap-3">
                <span
                  className={`font-stamp text-3xl leading-none ${report.suspicious ? 'text-verdict-missing' : 'text-verdict-unknown'}`}
                  aria-hidden
                >
                  {report.suspicious ? '▲' : '○'}
                </span>
                <h3
                  data-testid="steg-verdict"
                  className={`font-stamp text-3xl leading-none ${report.suspicious ? 'text-verdict-missing' : 'text-verdict-unknown'}`}
                >
                  {report.verdict}
                </h3>
              </div>
              <p className="mt-2 text-sm text-base-content/70">{report.summary}</p>
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <Exhibit label="File">{report.filename}</Exhibit>
              <Exhibit label="Elements analysed">
                {report.elements.toLocaleString()} ({report.kind})
              </Exhibit>
              <Exhibit label="Windows flagged">
                {report.windows_flagged} of {report.windows_total}
              </Exhibit>
              <Exhibit label="Suspected region">
                {report.suspected_region
                  ? `elements ${report.suspected_region.start.toLocaleString()}–${report.suspected_region.end.toLocaleString()}`
                  : 'none'}
              </Exhibit>
              <Exhibit label="Strongest byte-phase p">{formatP(report.phase_p)}</Exhibit>
              <Exhibit label="Whole-file chi-square p">{formatP(report.chi_square_p)}</Exhibit>
              {report.phase_n_lsb_guess !== null && (
                <Exhibit label="LSB count guess (rough)">{report.phase_n_lsb_guess}</Exhibit>
              )}
            </div>

            <div>
              <h3 className="font-stamp mb-2 text-lg">Evidence along the file</h3>
              <EvidenceStrip windows={report.windows} threshold={PHASE_THRESHOLD} elements={report.elements} />
              {report.windows_merged > 1 && (
                <p className="mt-1 text-xs text-base-content/60">
                  Each column merges {report.windows_merged} neighbouring windows (strongest evidence kept).
                </p>
              )}
            </div>

            {flaggedWindows.length > 0 && (
              <details className="text-sm" open={flaggedWindows.length <= 6}>
                <summary className="cursor-pointer font-medium">Flagged windows ({flaggedWindows.length})</summary>
                <table className="table-sm mt-2 table">
                  <thead>
                    <tr>
                      <th>Elements</th>
                      <th className="text-right">Byte-phase p</th>
                      <th className="text-right">Chi-square p</th>
                    </tr>
                  </thead>
                  <tbody className="font-exhibit text-xs">
                    {flaggedWindows.map((w) => (
                      <tr key={w.start}>
                        <td>
                          {w.start.toLocaleString()}–{w.end.toLocaleString()}
                        </td>
                        <td className="text-right">{formatP(w.phase_p)}</td>
                        <td className="text-right">{formatP(w.chi_square_p)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </details>
            )}
          </>
        )}

        {!report && !error && (
          <div className="border-base-300 text-base-content/50 border border-dashed p-6 text-center text-sm">
            Choose a file to see whether its low bits give it away.
          </div>
        )}
      </section>
    </div>
  )
}
