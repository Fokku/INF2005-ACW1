import { ApiError } from '../api/client'

/**
 * How a failed API call is shown: the backend's own error detail, plainly.
 *
 * A 501 (a core function raising NotImplementedError) still gets a signpost
 * naming the function, rather than an opaque error.
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
        </div>
      </div>
    )
  }

  const message = error instanceof Error ? error.message : String(error)
  // The capacity check is a required demo case, not a crash: say what it is.
  const capacity = error instanceof ApiError && error.body.error === 'capacity_exceeded'
  return (
    <div className="alert alert-error items-start">
      <span className="font-stamp text-xl leading-none" aria-hidden>
        ✕
      </span>
      <div className="min-w-0">
        <h3 className="font-medium">
          {capacity ? 'Blocked before embedding: the payload does not fit' : 'Something went wrong'}
        </h3>
        <p className="text-sm break-all">{message}</p>
      </div>
    </div>
  )
}
