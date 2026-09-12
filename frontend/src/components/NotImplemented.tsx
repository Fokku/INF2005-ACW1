import { ApiError } from '../api/client'

/**
 * What the UI shows while a backend feature is still a stub.
 *
 * Delete this component once every endpoint works. Until then it turns a 501
 * into a signpost: it names the exact function a teammate has to write.
 */
export function ErrorNotice({ error }: { error: unknown }) {
  if (error instanceof ApiError && error.isNotImplemented) {
    return (
      <div className="alert alert-warning items-start">
        <span className="font-stamp text-xl leading-none" aria-hidden>
          !
        </span>
        <div className="min-w-0">
          <h3 className="font-medium">Not implemented yet</h3>
          <p className="text-sm">This part of the backend is still a stub.</p>
          {error.body.todo && (
            <code className="font-exhibit mt-1 block text-xs break-all opacity-80">{error.body.todo}</code>
          )}
          <p className="mt-1 text-xs opacity-70">See TODO.md for who is picking this up.</p>
        </div>
      </div>
    )
  }

  const message = error instanceof Error ? error.message : String(error)
  return (
    <div className="alert alert-error items-start">
      <span className="font-stamp text-xl leading-none" aria-hidden>
        ✕
      </span>
      <div className="min-w-0">
        <h3 className="font-medium">Something went wrong</h3>
        <p className="text-sm break-all">{message}</p>
      </div>
    </div>
  )
}
