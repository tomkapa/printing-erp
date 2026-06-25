//! HTTP layer: router assembly, shared state, route handlers and limits.

mod auth_principal;
mod limits;
mod require;
mod router;
mod routes;
mod state;

pub(crate) use require::Require;
pub(crate) use router::router;
pub(crate) use state::AppState;
