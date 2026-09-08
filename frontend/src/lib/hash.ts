/**
 * SHA-256 of a file, computed in the browser with WebCrypto.
 *
 * This is DISPLAY ONLY. It backs the "same file before send / after download"
 * check in the party A to party B demo: party A hashes the stego file before
 * attaching it, party B hashes the downloaded file, and the two chips match.
 *
 * It has nothing to do with the media hash inside the payload — that one is
 * computed server-side over a stable representation of the samples, and the
 * browser must never try to reproduce it.
 *
 * Complete — no TODO.
 */
export async function sha256File(file: File | Blob): Promise<string> {
  const buffer = await file.arrayBuffer()
  const digest = await crypto.subtle.digest('SHA-256', buffer)
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}
