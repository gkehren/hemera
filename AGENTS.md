# AGENTS.md

This file defines the working agreement for AI agents contributing to Hemera.
It applies to the entire repository. More specific `AGENTS.md` files may refine
these rules for a subdirectory, but they must not weaken the security and ethical
requirements defined here.

## Project overview

Hemera is an open-source web protection scanner written in Go. It observes
publicly visible HTTP, DNS, TLS, DOM, and browser-network signals and produces
explainable detections for CDN/reverse proxies, WAFs, bot management products,
CAPTCHA/challenges, client-side fingerprinting, and related security services.

Hemera is a technical open-source project, not a SaaS product. Its priorities,
in order, are:

1. safety;
2. detection accuracy;
3. explainability;
4. reproducibility;
5. extensibility;
6. CLI and automation usability.

Prefer a few high-quality, evidence-backed detectors over broad but unreliable
coverage. A vendor-level signal must never automatically imply that a specific
product is enabled.

Read these documents before making architectural or security-sensitive changes:

- `README.md` — public project overview and current status;
- `docs/vision-and-goals.md` — direction, objectives, and non-goals;
- `docs/architecture.md` — component boundaries and planned data flow;
- `docs/roadmap.md` — current milestones and delivery order;
- `docs/security-and-ethics.md` — mandatory safety and ethical boundaries.

Repository documentation is authoritative for the implementation. The linked
Notion brief provides the original product context, but documentation and code
must remain synchronized as decisions evolve.

## Current project state

Hemera is in early development. The repository currently contains:

- the Go module `github.com/gkehren/hemera`, requiring Go 1.24 or later;
- a bootstrap CLI in `cmd/hemera` with help and version output;
- the normalized signal model in `pkg/model`;
- unit tests for the CLI and signal model.

Do not document planned behavior as implemented. In particular, the `scan`
command and detector pipeline do not exist until their roadmap steps are
completed and verified.

## Architecture boundaries

The intended pipeline is:

```text
target URL -> validation -> analyzers -> normalized signals
             -> detection rules -> confidence engine -> reporters
```

Preserve these boundaries:

- analyzers collect observations and emit normalized signals;
- the rule engine consumes signals and must not depend directly on `net/http`,
  DNS clients, TLS connections, or Chromium;
- scoring evaluates evidence and conflicts independently of presentation;
- reporters format results but do not perform detection;
- CLI code coordinates application behavior and remains thin.

Avoid creating empty packages for the complete planned tree. Add a package when
a working vertical slice needs it, and keep the package responsibility narrow.

### Signal model

`pkg/model.Signal` is shared evidence, not a final detection. Its `Confidence`
field expresses certainty in the observation and is bounded between 0 and 1. It
does not represent a product's final detection score.

When changing `Signal`, `SignalType`, validation rules, or JSON field names:

- explain why the common model needs the change;
- preserve compatibility unless a breaking change is intentional and documented;
- update validation, JSON round-trip tests, and architecture documentation;
- update every producer, consumer, and fixture in the same change;
- never place analyzer-specific behavior in the common model.

## Security and ethical requirements

Treat every URL, redirect, DNS answer, response, document, and browser action as
untrusted. Security controls are core functionality, not optional hardening.

Any network implementation must account for:

- HTTP/HTTPS scheme allowlisting;
- loopback, private, link-local, multicast, unspecified, and metadata addresses;
- IPv4, IPv6, alternate IP representations, and mixed DNS answers;
- DNS rebinding and validation of the address actually used;
- redirect revalidation;
- connection, response-size, decompression, concurrency, and total-time limits.

Hemera must never add capabilities to solve or bypass challenges, spoof
fingerprints for evasion, send exploit-oriented WAF payloads, perform credential
attacks, crawl aggressively, or facilitate denial of service. Browser automation
must preserve sandboxing and normal navigation behavior.

Minimize collected evidence. Redact cookies, authorization values, session
tokens, and other secrets by default. Public fixtures must be synthetic or
explicitly redistributable and must not contain live credentials or personal
data.

If a requested change conflicts with these requirements, stop and explain the
conflict instead of implementing it.

## Go conventions

- Use the Go version declared in `go.mod`; do not raise it without a concrete
  requirement and documentation update.
- Run `gofmt` on every changed Go file.
- Prefer the standard library. Add a dependency only when its maintenance,
  security, and complexity cost is justified by a clear project need.
- Run `go mod tidy` after dependency changes and review both `go.mod` and
  `go.sum`.
- Use idiomatic, small packages with explicit responsibilities. Avoid generic
  `util`, `helpers`, or `common` packages.
- Accept interfaces at the consumer boundary; do not introduce interfaces only
  for hypothetical future flexibility.
- Keep exported APIs minimal. Add Go doc comments to every exported identifier.
- Return errors instead of logging and continuing. Wrap errors with useful
  context using `%w` when callers may inspect the cause.
- Use sentinel errors only when callers need `errors.Is`; use typed errors only
  when callers need structured details.
- Pass `context.Context` as the first argument to operations that can block,
  perform I/O, or require cancellation. Do not store contexts in structs.
- Make resource ownership explicit and close bodies, files, connections, and
  browser sessions deterministically.
- Avoid global mutable state. Values injected at build time, such as the CLI
  version, are acceptable when narrowly scoped.
- Do not use `panic` for expected runtime or input errors.
- Keep platform behavior portable across Linux, macOS, and Windows unless a
  platform-specific implementation is isolated and tested.

## CLI and output conventions

- Commands and flags use lowercase kebab-case.
- Help and version requests write to stdout and exit with code 0.
- User/input errors write to stderr and exit with code 2.
- Scan/runtime failures should write actionable context to stderr and use a
  non-zero code distinct from invalid CLI usage when that command is added.
- Keep stdout machine-readable when a structured output mode is selected.
- Do not mix logs or progress indicators into JSON output.
- JSON field names use `snake_case` and are treated as a compatibility contract
  once documented as stable.
- Explain detections with evidence; never output an unqualified vendor/product
  assertion from ambiguous signals.

## Testing requirements

Tests are part of the implementation, not a follow-up task.

- Add or update tests for every behavior change and bug fix.
- Prefer table-driven tests for input matrices and validation rules.
- Use `t.Parallel()` only when the test has no shared mutable state, process-wide
  environment mutation, fixed port, or shared filesystem dependency.
- Test public behavior and meaningful invariants rather than private line-by-line
  implementation details.
- Include boundary and failure cases, especially for parsing, confidence values,
  redirects, address classification, timeouts, and resource limits.
- Unit tests must be deterministic and must not depend on live websites, public
  DNS, wall-clock timing, or external services.
- Use `httptest`, local fakes, and checked-in fixtures for network behavior.
- Store fixtures under `testdata/`; keep them small, sanitized, attributable, and
  paired with expected results.
- Every detector must include positive, negative, ambiguity, and regression
  fixtures before it is considered supported.
- Do not weaken, skip, or delete a failing test merely to make the suite pass.

Before handing off a Go change, run from the repository root:

```sh
gofmt -w <changed-go-files>
go vet ./...
go test ./...
go test -race ./...
go build -o /tmp/hemera ./cmd/hemera
git diff --check
```

Use a writable temporary `GOCACHE`/`GOMODCACHE` when the execution environment
does not permit writes to the default Go caches. Report any check that could not
be run and why. Coverage is a diagnostic, not a target to game; new core model or
security code should nevertheless receive thorough branch coverage.

## Documentation conventions

- Write code, comments, public documentation, CLI text, issues, and commit
  messages in English.
- Use concise, direct language and define security-specific terminology.
- Keep Markdown compatible with GitHub and run `git diff --check`.
- Use relative links for files within the repository.
- Update `README.md` when setup, user-facing behavior, status, or supported
  capabilities change.
- Update `docs/architecture.md` when component boundaries, shared models, or data
  flow change.
- Update `docs/security-and-ethics.md` when the threat model, data handling, or
  network/browser behavior changes.
- Update `docs/roadmap.md` only after a task is implemented and verified. Never
  check an item based on partial scaffolding or intent.
- Distinguish current behavior from planned behavior explicitly.
- Add examples only when they are runnable today, or label them clearly as
  planned output.

## Git and worktree safety

- Inspect `git status` before editing and before handoff.
- Treat pre-existing modifications as user-owned. Preserve them and avoid
  unrelated rewrites.
- Keep changes focused on the requested scope.
- Never use destructive commands such as `git reset --hard`, forced checkout, or
  broad cleanup commands to resolve local state.
- Do not commit generated binaries, coverage files, local caches, secrets, IDE
  state, or temporary artifacts. Keep `.gitignore` aligned with new tooling.
- Do not modify git history, push, open a pull request, or create a commit unless
  the user explicitly asks for that action.
- When asked to commit, review the complete staged diff and ensure it contains
  only intentional changes.

## Commit conventions

All commit messages must be written in English, use Conventional Commits, and
describe the change in enough detail for a future contributor to understand its
purpose.

Format:

```text
<type>(<optional-scope>): <imperative summary>

<detailed body explaining what changed and why>

<optional footer>
```

Rules:

- Use an imperative, lowercase summary without a trailing period.
- Keep the summary focused and preferably at or below 72 characters.
- Include a detailed body in every commit. Describe motivation, important
  implementation choices, safety implications, and tests when relevant.
- Wrap body lines at approximately 72 characters.
- Use `BREAKING CHANGE:` in the footer for incompatible public API, CLI, rule
  schema, or stable JSON changes.
- Reference issues in footers when applicable, for example `Closes #42`.
- Never add an AI agent as a commit co-author or include an AI attribution
  trailer such as `Co-authored-by`. Only the human developer may be credited as
  the author or co-author of a commit.
- Do not use vague summaries such as `update`, `fix stuff`, or `changes`.
- Do not mix unrelated refactors, documentation, and behavior changes in one
  commit merely to reduce commit count.

Preferred types:

- `feat` — new user-visible or domain capability;
- `fix` — defect correction;
- `docs` — documentation-only change;
- `test` — test-only change;
- `refactor` — behavior-preserving code restructuring;
- `perf` — measured performance improvement;
- `build` — build system or dependency change;
- `ci` — continuous integration change;
- `chore` — narrowly scoped repository maintenance;
- `security` — security hardening or vulnerability correction.

Examples:

```text
feat(model): add normalized signal validation

Define the supported signal types and reject missing source or key values.
Bound observation confidence to finite values between zero and one, and add
JSON round-trip coverage for the shared analyzer contract.
```

```text
security(scanner): reject private redirect targets

Revalidate every redirect after DNS resolution so public URLs cannot pivot to
loopback, private, link-local, or cloud metadata addresses. Add IPv4 and IPv6
regression cases using deterministic local fakes.
```

## Agent workflow

For each task:

1. Read the relevant documentation and inspect the current worktree.
2. Derive concrete acceptance criteria from the request and roadmap.
3. Implement the smallest complete vertical change that satisfies those criteria
   without weakening future architecture or safety.
4. Add or update tests with the implementation.
5. Synchronize affected documentation and roadmap status.
6. Run the proportional verification suite, inspect the final diff, and ensure no
   generated or sensitive artifacts are included.
7. Report what changed, which checks passed, any checks not run, and remaining
   limitations. Do not claim unimplemented behavior.

If requirements are ambiguous, inspect existing code and documentation first.
Make a conservative assumption only when it is reversible and does not alter the
security model or public contract; otherwise ask for clarification.

## Definition of done for a change

A change is complete only when:

- the requested behavior is implemented rather than merely scaffolded;
- architecture and security boundaries remain intact;
- relevant success, boundary, and failure tests pass;
- formatting, vetting, building, and repository checks pass where applicable;
- documentation accurately describes the resulting state;
- the roadmap is updated only if its full acceptance criterion is satisfied;
- `git status` contains no accidental binary, secret, cache, or temporary file;
- the final handoff clearly states verification results and known limitations.
