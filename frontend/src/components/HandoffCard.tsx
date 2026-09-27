import { useEffect, useMemo } from 'react'
import type { ProtectResult, StartMode } from '../types'
import { Exhibit } from './Exhibit'

/**
 * Everything party B needs, on one card (spec Section 5: "showing the stego
 * object being sent from party A to party B").
 *
 * Party A reads this out — or sends it alongside the email attachment — so
 * party B can fill the Verify tab: the media ID, the LSB count, the copies,
 * how to find the start, the file's SHA-256 (to prove it survived the trip)
 * and the signer's key fingerprint (to prove they hold the right public key).
 * The passphrase is deliberately NOT on the card: it travels out of band.
 */
export function HandoffCard({
  result,
  mediaId,
  startMode,
  onVerify,
  onAttack,
  busy,
}: {
  result: ProtectResult
  mediaId: string
  startMode: StartMode
  onVerify: () => void
  onAttack: () => void
  busy: boolean
}) {
  const publicKeyUrl = useMemo(
    () => URL.createObjectURL(new Blob([result.signer_public_key_pem], { type: 'application/x-pem-file' })),
    [result.signer_public_key_pem],
  )
  useEffect(() => () => URL.revokeObjectURL(publicKeyUrl), [publicKeyUrl])

  return (
    <div className="border-base-300 space-y-4 rounded-sm border p-4">
      <div>
        <h2 className="font-stamp text-lg">Hand-off to party B</h2>
        <p className="mt-1 text-xs text-base-content/60">
          Send the stego file as an email attachment. Share the passphrase and this card out of band;
          party B enters the same values on the Verify tab.
        </p>
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        <Exhibit label="Media ID">{mediaId}</Exhibit>
        <Exhibit label="Read with">
          {result.n_lsb} LSB · {result.redundancy} {result.redundancy === 1 ? 'copy' : 'copies'}
        </Exhibit>
        <Exhibit label="Start location">
          {startMode === 'derived'
            ? 'derived from the shared passphrase'
            : `explicit offset ${result.start_offset.toLocaleString()}`}
        </Exhibit>
        <Exhibit label="Frame">{result.sealed ? 'sealed (needs the passphrase)' : 'plaintext header'}</Exhibit>
      </div>
      <Exhibit label="Stego file SHA-256 (compare after download)">{result.stego.sha256}</Exhibit>
      <Exhibit label="Signer public key fingerprint">{result.signer_fingerprint}</Exhibit>

      <div className="flex flex-wrap gap-2">
        <button type="button" className="btn btn-primary btn-sm" disabled={busy} onClick={onVerify}>
          {busy && <span className="loading loading-spinner loading-xs" />}
          Verify this file →
        </button>
        <button type="button" className="btn btn-outline btn-sm" disabled={busy} onClick={onAttack}>
          Attack this file →
        </button>
        <a href={publicKeyUrl} download="signer.pub.pem" className="btn btn-outline btn-sm">
          Download public key
        </a>
      </div>
    </div>
  )
}
