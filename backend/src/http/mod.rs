//! HTTP layer: router assembly, shared state, route handlers and limits.

mod limits;
mod router;
mod routes;
mod state;

pub(crate) use router::router;
pub(crate) use state::AppState;
