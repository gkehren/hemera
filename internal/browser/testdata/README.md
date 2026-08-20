# Hermetic browser fixtures

This directory contains only synthetic resources created for Hemera tests. The
fixtures do not copy or contact a live website, CDN, security vendor, or other
third party. Strings resembling credentials, tokens, sessions, and cookie values
are deliberately fake and exist only to test evidence minimization.

`cases.json` is the versioned manifest. Its `routes` array declares every
request the fixture server may accept. A route has a unique name and
path/query pair, an expected status and content type, and either a relative
`file`, a same-origin relative `redirect_to`, or a test-owned active `behavior`.
Routes may declare an `expected_authorization` value to prove that synthetic
credentials reached the fixture while remaining absent from captured metadata.
The `cases` array defines each capture scenario's entry and final route,
expected final marker, DOM markers, exact unique traffic set, semantic
`traffic_dependencies`, scripts, iframes, cookie names, and values that must
never occur in minimized metadata. Dependencies form an acyclic partial order.
Missing, extra, duplicate, and dependency-violating requests fail, but routes
without a dependency may arrive in either order. Integration tests do not wait
on the marker; explicit fixture network handshakes keep production's post-load
network-idle/deadline phase active until delayed work is complete.

The `limits` assets are adversarial synthetic inputs for redirects, compression,
post-load DOM growth, continuous requests, long polling, recursive frames,
workers, popups, WebSockets, and downloads. Unsupported child targets are
deliberately blocked.

To add a fixture:

1. Add a small asset beneath this directory using only relative, same-origin
   references. Absolute and protocol-relative HTTP(S) references are rejected.
2. Declare its route in `cases.json`; never add an absolute HTTP(S) reference.
3. Add or update a case with the exact expected traffic set, only the ordering
   dependencies required by browser semantics, and the expected observations.
4. Run `go test ./internal/browser`. This validates the complete manifest and
   corpus without requiring Chromium.
5. When Chromium is installed, also run
   `go test -tags=browser_integration ./internal/browser`.

Keep behaviors requiring timing, counters, or generated local destinations in
Go. Everything else should be a checked-in asset so test inputs remain visible,
reviewable, and reproducible.
