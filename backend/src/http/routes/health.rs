//! Liveness and readiness probes.
//!
//! `live` answers "is the process up?"; `ready` answers "can it serve traffic?"
//! by probing PostgreSQL and Redis, each behind a bounded timeout (§5).

use crate::db;
use crate::http::limits;
use crate::http::state::AppState;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::Serialize;
use tokio::time::timeout;

/// Service identifier reported by the liveness probe.
const SERVICE: &str = "erp-server";

/// Body of the liveness response.
#[derive(Debug, Serialize)]
pub(crate) struct LiveBody {
    status: &'static str,
    service: &'static str,
    uptime_secs: u64,
}

/// Body of the readiness response.
#[derive(Debug, Serialize)]
pub(crate) struct ReadyBody {
    status: &'static str,
    database: bool,
    redis: bool,
}

/// `GET /health/live` — process is running.
pub(crate) async fn live(State(state): State<AppState>) -> Json<LiveBody> {
    Json(LiveBody {
        status: "ok",
        service: SERVICE,
        uptime_secs: state.uptime_secs(),
    })
}

/// `GET /health/ready` — backing services are reachable.
pub(crate) async fn ready(State(state): State<AppState>) -> (StatusCode, Json<ReadyBody>) {
    let database = check_database(&state).await;
    let redis = check_redis(&state).await;
    let healthy = database && redis;

    let code = if healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    let body = ReadyBody {
        status: if healthy { "ready" } else { "degraded" },
        database,
        redis,
    };
    (code, Json(body))
}

/// Probes PostgreSQL liveness within [`limits::HEALTH_CHECK_TIMEOUT`].
async fn check_database(state: &AppState) -> bool {
    match timeout(limits::HEALTH_CHECK_TIMEOUT, db::ping(&state.db)).await {
        Ok(Ok(())) => true,
        Ok(Err(error)) => {
            tracing::warn!(error = ?error, "database readiness check failed");
            false
        }
        Err(_elapsed) => {
            tracing::warn!("database readiness check timed out");
            false
        }
    }
}

/// Probes Redis liveness within [`limits::HEALTH_CHECK_TIMEOUT`].
async fn check_redis(state: &AppState) -> bool {
    let mut conn = state.redis.clone();
    let ping = async move {
        let _pong: String = redis::cmd("PING").query_async(&mut conn).await?;
        Ok::<(), redis::RedisError>(())
    };

    match timeout(limits::HEALTH_CHECK_TIMEOUT, ping).await {
        Ok(Ok(())) => true,
        Ok(Err(error)) => {
            tracing::warn!(error = ?error, "redis readiness check failed");
            false
        }
        Err(_elapsed) => {
            tracing::warn!("redis readiness check timed out");
            false
        }
    }
}
