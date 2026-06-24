//! Hard limits and tuning constants for authentication (CLAUDE.md §5).
//!
//! Every bound lives here, named and documented with *why this number*, rather
//! than as a magic literal in auth logic. Value-type bounds that are domain
//! invariants (email/password length) live next to their `TryFrom` in
//! `domain/`; this file holds auth-*mechanism* numbers (tokens, JWT, argon2).

use std::time::Duration;

/// Minimum HS256 signing-secret length, in bytes. HS256 keys should carry at
/// least 256 bits of entropy; a shorter secret weakens every access token.
/// Asserted when the [`AuthContext`](crate::auth::AuthContext) is built.
pub(crate) const MIN_JWT_SECRET_BYTES: usize = 32;

/// Length of the random secret inside an opaque (refresh/reset) token, in bytes.
/// 256 bits is infeasible to guess; it is generated from the OS CSPRNG.
pub(crate) const OPAQUE_SECRET_BYTES: usize = 32;

/// Maximum accepted opaque-token length, in bytes. The wire form is
/// `<uuid:36>.<base64url(32 bytes):43>` = 80 bytes; 128 caps malformed input
/// before parsing (CLAUDE.md §5).
pub(crate) const MAX_OPAQUE_TOKEN_BYTES: usize = 128;

/// Tolerated forward clock skew when validating a token's `iat`, in seconds. A
/// token minted slightly "in the future" by another instance is accepted; one
/// minted far ahead is rejected as forged. Kept small.
pub(crate) const MAX_IAT_SKEW_SECS: i64 = 5;

/// argon2id memory cost, in KiB (production). OWASP's baseline for interactive
/// logins is 19 MiB; combined with the iteration count below it targets a few
/// tens of milliseconds per hash on server hardware.
#[cfg(not(test))]
pub(crate) const ARGON2_MEMORY_KIB: u32 = 19 * 1024;

/// argon2id memory cost, in KiB (tests). The production cost adds tens of ms per
/// hash; the integration suite hashes on many paths, so tests use the algorithm
/// at a deliberately cheap cost. Security of stored hashes is unaffected — only
/// test wall-clock is.
#[cfg(test)]
pub(crate) const ARGON2_MEMORY_KIB: u32 = 8;

/// argon2id time cost (iterations). OWASP baseline pairs 2 passes with 19 MiB.
#[cfg(not(test))]
pub(crate) const ARGON2_ITERATIONS: u32 = 2;

/// argon2id time cost (iterations) for tests — the minimum the algorithm allows.
#[cfg(test)]
pub(crate) const ARGON2_ITERATIONS: u32 = 1;

/// argon2id parallelism (lanes). One lane suits a synchronous per-request hash.
pub(crate) const ARGON2_PARALLELISM: u32 = 1;

/// Upper bound on an auth database round-trip from a handler (CLAUDE.md §5),
/// mirroring `http::limits::TENANT_QUERY_TIMEOUT`. Generous for OLTP work, tight
/// enough to free the pooled connection on a stalled server or lock wait.
pub(crate) const AUTH_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Compile-time guard: the opaque-token cap must admit a well-formed token.
const _: () = assert!(MAX_OPAQUE_TOKEN_BYTES >= 36 + 1 + 43);
