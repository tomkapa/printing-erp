# CLAUDE.md — Patom engineering rules

How we write Rust for Patom. Binding, not advisory. Read `SPEC.md` for the data model and pipeline before non-trivial changes.

Priorities, in order: **correctness, safety, clarity, performance**.
Lineage: TigerBeetle TIGER_STYLE + NASA Power of Ten.

Stack: tokio runtime, axum (HTTP), tower (middleware), sqlx (Postgres), serde (boundary), thiserror (libraries/modules), anyhow (binaries only), tracing + tracing-opentelemetry + opentelemetry-semantic-conventions (instrumentation).

---

## 1. Types encode invariants. Primitives are the exception.

If a value carries any invariant — logical or business — wrap it in a newtype. Bare `String` / `u32` / `Uuid` are reserved for values that genuinely have none.

**Parse, don't validate.** Values cross into the typed world exactly once, at the boundary, via `TryFrom` / `TryInto`. The smart constructor is `impl TryFrom<Raw> for Domain`; the fallible conversion is the only way in. No public field, no free constructor.

```rust
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("malformed: {0}")]
    Malformed(&'static str),
    #[error("out of range: {0}")]
    OutOfRange(&'static str),
    #[error("too long: max {max}, got {got}")]
    TooLong { max: usize, got: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AgentId(Uuid);

impl AgentId {
    pub fn as_uuid(self) -> Uuid { self.0 }
}

impl TryFrom<&str> for AgentId {
    type Error = ParseError;
    fn try_from(raw: &str) -> Result<Self, Self::Error> {
        Uuid::parse_str(raw).map(Self).map_err(|_| ParseError::Malformed("agent_id"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Depth(u16);

impl Depth {
    pub const CAP: Self = Self(16);
    pub fn get(self) -> u16 { self.0 }
}

impl TryFrom<u16> for Depth {
    type Error = ParseError;
    fn try_from(n: u16) -> Result<Self, Self::Error> {
        if n > Self::CAP.0 { return Err(ParseError::OutOfRange("depth")); }
        Ok(Self(n))
    }
}
```

- Newtype every id. `String` / `Uuid` for an id is a review-blocking bug.
- Newtype every bounded numeric. The `TryFrom` impl enforces the bound.
- Parse every external input at the boundary via `TryFrom` / `TryInto`. No `as` narrowing inside the core; no raw struct construction across module boundaries.
- Prefer sum types (`enum`) over `bool` + `Option<...>`. Exhaustive `match` proves totality; `#[deny(non_exhaustive_omitted_patterns)]` is on.
- `serde` runs only at the boundary. Use `#[serde(try_from = "RawShape")]` so deserialization funnels through the same smart constructor — schemas feed `TryFrom`, they do not replace it.
- No `pub` on newtype inner fields; expose readers (`as_uuid`, `get`) only.

## 2. tracing + OpenTelemetry is the only instrumentation API.

Spans, events, and logs go through `tracing` bridged to OTel via `tracing-opentelemetry`. Attribute names come from `opentelemetry-semantic-conventions`. No `println!`, `eprintln!`, `dbg!`, or `log` crate in app code. A dev printer is allowed only behind `#[cfg(debug_assertions)]`.

**Spans.**
- Every externally-triggered unit of work opens a span via `#[tracing::instrument]` or `info_span!`.
- Names are stable and low-cardinality (`session.turn`, `hook.evaluate`). Dynamic values go on fields, never in the name.
- Custom attributes use `patom.*`: `patom.agent.id`, `patom.session.id`, `patom.tenant.id`, `patom.chain.id`, `patom.depth`, `patom.hook.decision`.
- On error: emit a `tracing::error!` event with `error = ?e` inside the span; the OTel bridge sets span status to ERROR. Don't drop the error and set status separately — both come from the one event.
- Spans end on every path. Either `#[instrument]` (RAII) or `let _g = span.enter()` bound to a scope guard. Never `span.in_scope` straddling an `await`.

**Logs.**
- Severity ∈ `TRACE | DEBUG | INFO | WARN | ERROR`. `ERROR` = user-visible failure. The Rust analogue of `FATAL` is `panic!` — process cannot continue.
- Structured only: `info!(event = "session.turn.started", patom.session.id = %sid, depth = depth.get())`. Never interpolate values into the message string.
- PII is `DEBUG`-only and stripped by production exporters.
- HTTP entry uses `tower_http::trace::TraceLayer` so every axum request opens a root span automatically.

**Metrics.**
- `opentelemetry::metrics::Meter`, fed from the same OTel pipeline.
- Every bounded loop has a saturation counter.
- Every channel/queue has depth and age-of-oldest gauges.
- Hook decisions are counter attributes, not separate spans.

## 3. TDD. Failing test first. Gates are non-negotiable.

Write the failing test before the implementation. A PR without a preceding test commit is reverted.

**Cycle.**
1. **Red.** Smallest test that expresses the next behavior. Confirm it fails for the expected reason — not a compile error, not a typo.
2. **Green.** Minimum code to pass. Nothing the test does not force.
3. **Refactor.** Only with the suite green.

**Exit gates — all must be green:**
- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo check --all-targets --all-features`
- `cargo test --all-features` (or `cargo nextest run`)
- the e2e harness for the changed surface
- `cargo deny check` and `cargo audit` (CI)

Any gate red → task is not done. No commit, no PR, no "done".

**Test shape.**
- One behavior per test.
- Test observable behavior at a public boundary. Never reach into `pub(crate)` internals from integration tests; never widen a `pub` just for a test.
- Real Postgres in integration tests via `#[sqlx::test]` (or `testcontainers`). Mock only paid external services and external HTTP.
- Coverage via `cargo-llvm-cov`: 80% lines overall, 100% on the hook evaluator, per-agent lease manager, and idempotency-key generator.

## 4. Control flow: simple, explicit, bounded, non-recursive.

- **No recursion.** Replace with an explicit loop over a bounded `VecDeque` or stack. A function calling itself is a review-blocking bug. Async recursion (`Box::pin` of `async fn`) is doubly banned.
- **No clever abstractions.** Introduce a trait or generic only when (a) it maps to a concept in `SPEC.md` and (b) the same code appeared ≥3 times saying the same thing. Three similar `impl` blocks beat a premature trait.
- **Push `if`s up, `for`s down.** Branch at the top of the call tree; loop at the leaves over primitive data.
- **State invariants positively.** `if depth < Depth::CAP`, not `if depth >= Depth::CAP { ... } else`.
- **Split compound conditions.** `assert!(a); assert!(b);` beats `assert!(a && b);`. Nested `if` beats `&&`-chained guards.
- **Function length ≤ 70 lines.** Hard ceiling. Closures count toward the enclosing function.
- Early-return `?` propagation is fine. Mid-function fast-path `return` is fine. `return` buried deep inside a loop is not — extract the loop body.

## 5. Everything has a limit. Enforce in code.

- Every `for` / `while` / `loop` has an explicit upper bound, asserted on entry. Bare `loop {}` requires a `break` condition tied to a counter or external signal.
- Every channel is bounded: `tokio::sync::mpsc::channel(N)`. `unbounded_channel` is banned. `broadcast::channel(N)` is bounded by construction.
- Every `await` against I/O is wrapped in `tokio::time::timeout(...)`. `fetch`, sqlx queries, hook RPCs — all of them. `ask` timeouts come from SPEC.
- Every batch has a size cap: `MAX_RETRIEVAL`, `MAX_HOOKS_PER_EVENT`, `MAX_TURNS_PER_COMPACTION`.
- Every string crossing a trust boundary has a length cap. axum: `DefaultBodyLimit::max(N)`. sqlx column reads of unbounded `TEXT` are banned without an explicit `LEFT(col, N)` or app-side length check.
- Constants live in `limits.rs` per subsystem (e.g. `session/limits.rs`). Named, exported, doc-commented with *why this number*. Magic numbers in logic are banned.

Unknown bound → pick a pessimistic one and add a metric to watch it.

## 6. Assertions detect programmer errors. Failure crashes the process.

- **Operating error** — expected (flaky network, bad input, DB contention). Return a `Result<T, E>` with `E` from §12; handle; retry where safe.
- **Assertion failure** — unexpected. The code's model of the world is wrong. The only correct response is to crash; continuing corrupts more state.

- Use `assert!` / `assert_eq!` (kept in release). `debug_assert!` is banned in non-test code — assertions stripped by the optimizer aren't assertions.
- Set `[profile.release] panic = "abort"` so a panic terminates the process immediately. The lease expires, another worker resumes (SPEC §Retry and idempotency).
- Assert at boundaries: pre/post-conditions, invariants around compound updates, immediately after reads that should have a known shape.
- Assert both what you expect **and** what you don't. `assert!(x > 0); assert!(x < cap);`
- Density: ≥2 assertions per non-trivial function.
- `assert!` is for invariants; `Result<T, E>` is for expected failures. Never mix.
- `unwrap()` is banned outside `#[cfg(test)]`. `expect("invariant: <reason>")` is acceptable as a named assertion when the invariant is established within the function; the message is mandatory.

## 7. Strictest compiler / clippy settings. Warnings are errors.

Workspace-level lints (`Cargo.toml [workspace.lints]`):

```toml
[workspace.lints.rust]
unsafe_code = "forbid"
unreachable_pub = "warn"
missing_debug_implementations = "warn"
rust_2024_compatibility = "warn"
nonstandard_style = "deny"
future_incompatible = "deny"

[workspace.lints.clippy]
all = { level = "deny", priority = -1 }
pedantic = { level = "warn", priority = -1 }
nursery = { level = "warn", priority = -1 }
cargo = { level = "warn", priority = -1 }
unwrap_used = "deny"
expect_used = "warn"   # require justification comment
panic = "warn"         # ditto; assertions are an explicit allow
todo = "deny"
unimplemented = "deny"
dbg_macro = "deny"
print_stdout = "deny"
print_stderr = "deny"
as_conversions = "deny"
mem_forget = "deny"
float_cmp = "deny"
```

CI: `RUSTFLAGS="-D warnings"` and `cargo clippy ... -- -D warnings`. No tolerated warnings — fix the code or remove the lint with PR justification.

**Banned:**
- `unsafe` blocks. Any exception requires `#[allow(unsafe_code)]` with a linked SPEC reference and a safety proof comment.
- `unwrap()` outside `#[cfg(test)]`. `expect()` only with a justified message.
- `as` for narrowing or sign-changing casts. Use `TryFrom` / `TryInto`.
- `mem::transmute`, `Box<dyn Any>`, `std::any::Any` in app code.
- `#[allow(dead_code)]` / `#[allow(unused)]` without a linked issue and expiry.
- `Rc<RefCell<...>>` in any path reachable from an `async fn`. Use `Arc<Mutex<...>>` or, better, a channel.
- Floating tasks: `tokio::spawn(...)` whose `JoinHandle` is dropped — use `JoinSet` or await the handle.
- Bare `Box<dyn std::error::Error>` across a module boundary. Errors are typed (§12).
- `String` as the error type of any returned `Result`.

## 8. Zero-dependency bias.

Every runtime dep costs supply-chain risk, build time, and surface area. Adding one to `Cargo.toml` requires a PR paragraph: what it does, why not <200 LOC in-tree, who owns the upgrade cadence. Dev deps: lower bar, not zero. `cargo deny` (licenses, advisories, bans) and `cargo audit` (RustSec) run in CI; failures block merge.

## 9. Static allocation at module boundaries.

Pools, caches, and rate-limiter state are sized at startup from config and built once.

- `sqlx::PgPool` constructed via `PgPoolOptions::new().max_connections(...).acquire_timeout(...)` in `main`, threaded through as `&PgPool`.
- `reqwest::Client` reused across calls; per-host connection caps set at construction.
- Caches: bounded LRU (`moka` if dep-justified, else in-tree fixed-size).
- Rate limiters: token-bucket sized at startup.
- Module-level state via `OnceLock` / `LazyLock`. `static mut` is banned.

Growing-on-demand structures inside a worker hot path are banned — use a bounded data structure (§5).

## 10. No string concatenation into SQL. Ever.

- Use runtime `sqlx` with bound parameters: `sqlx::query("SELECT ... WHERE id = $1").bind(id)`, mapped via `#[derive(sqlx::FromRow)]` + `TryFrom<Row>` at the boundary (§1). `format!` into a query string is a review-blocking bug.
- Do not use the compile-time `query!` / `query_as!` macros. Drift is caught by the `#[sqlx::test]` suite (§3).
- Dynamic identifiers (table, column, sort key) pass through an allowlist — match a domain enum to a `&'static str`. Never an interpolated value.
- RLS (SPEC §Tenancy) defends against a missing `WHERE tenant_id`; this rule defends against injection.

## 11. Tests own the clock.

No production code calls `Instant::now`, `SystemTime::now`, `chrono::Utc::now`, or `tokio::time::sleep` directly. Production code that needs time takes a `Clock`:

```rust
pub trait Clock: Send + Sync + 'static {
    fn now(&self) -> std::time::Instant;
    fn now_utc(&self) -> chrono::DateTime<chrono::Utc>;
}
```

Real clock in prod, deterministic fake (`Arc<TestClock>` with `advance(Duration)`) in tests. For tokio timers, tests use `tokio::time::pause()` + `tokio::time::advance(...)`. `#[tokio::test(start_paused = true)]` is the default for any test that touches scheduling. Flaky real timers are the single biggest waste of debugging hours.

## 12. One error type per module boundary.

Each module exports a `thiserror`-derived enum describing every failure. Exhaustive `match` (§1) forces every caller to handle every variant. `anyhow::Error` is reserved for binary entry points (`main.rs`, top-level handler glue) — it never appears in a library/module signature. Bare `panic!` / `unreachable!` across a module boundary is a review-blocking bug; panics are reserved for assertions (§6).

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("lease expired for agent {agent}")]
    LeaseExpired { agent: AgentId },
    #[error("depth {depth:?} exceeds cap")]
    DepthExceeded { depth: Depth },
    #[error("tenant mismatch: expected {expected:?}, got {got:?}")]
    TenantMismatch { expected: TenantId, got: TenantId },
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}
```

For axum handlers, the module's error type implements `IntoResponse` once, so HTTP mapping lives next to the variants and can't drift. `From` impls bridge sub-errors at the seams; the `?` operator is the only error-propagation mechanism in app code.

## 13. Migration discipline.

Every schema change has a forward `sqlx` migration and a tested reversible rollback, both verified against a staging dump before merge. Online migrations (`NOT NULL` on a large table, column-type change, non-`CONCURRENTLY` index) require a written rollout plan in the PR. `sqlx migrate add -r <name>` for paired up/down; never edit a migration after it's merged; never squash.
