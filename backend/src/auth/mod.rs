//! Authentication: password hashing, JWT access tokens, rotating refresh
//! tokens, and password reset (issue #12).
//!
//! Tenancy interplay: the request tenant is derived from a verified access-token
//! claim (`http::AuthPrincipal`), never a client-supplied header — RLS
//! (SPEC.md §Tenancy) is only a backstop against a *missing* filter, not against
//! a caller who claims another tenant. Refresh and reset tokens are *routable*
//! (`<tenant>.<secret>`) so the server can open the correct tenant transaction
//! before looking a token up, since the access token may already be expired.

mod claims;
mod context;
mod error;
#[cfg(test)]
mod fixtures;
mod limits;
mod login;
mod logout;
mod notifier;
mod opaque;
mod password;
mod refresh;
mod reset;
mod session;
mod tenants;

pub(crate) use context::AuthContext;
pub(crate) use error::AuthError;
pub(crate) use login::{LoginRequest, login};
pub(crate) use logout::{LogoutRequest, logout};
pub(crate) use notifier::LoggingNotifier;
// Exposed so the user-management API (RBAC, #13) hashes an admin-set initial
// password through the exact same argon2id path as login, rather than
// duplicating the parameters.
pub(crate) use password::{PasswordError, hash_password};
pub(crate) use refresh::{RefreshRequest, refresh};
pub(crate) use reset::{ForgotRequest, ResetRequest, forgot_password, reset_password};
pub(crate) use session::TokenPair;
