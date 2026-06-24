//! HTTP layer: router assembly, shared state, route handlers and limits.

mod auth_principal;
mod limits;
mod router;
mod routes;
mod state;

pub(crate) use auth_principal::AuthPrincipal;
pub(crate) use router::router;
pub(crate) use state::AppState;
