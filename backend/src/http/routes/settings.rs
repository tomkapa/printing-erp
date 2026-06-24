//! Business-configuration routes (Issue #15).
//!
//! `GET /settings` returns the requesting tenant's business configuration;
//! `PUT /settings` creates or replaces it (an idempotent upsert — SPEC.md
//! §Retry and idempotency). Both resolve the tenant from the authenticated
//! [`AuthPrincipal`] and run inside a tenant-scoped transaction
//! ([`db::begin_tenant_tx`]), so Row-Level Security keys every read and write to
//! the caller's tenant.

use crate::db;
use crate::domain::{
    Address, BusinessSettings, BusinessSettingsRow, EmailAddress, LogoRef, Phone, TaxCode, TenantId,
};
use crate::http::AuthPrincipal;
use crate::http::limits;
use crate::http::state::AppState;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use sqlx::PgPool;
use thiserror::Error;
use tokio::time::timeout;

/// Reads the full settings row, scoped to the active tenant by RLS.
const SELECT_SETTINGS: &str = "SELECT legal_name, tax_code, address, phone, email, logo_url, \
     currency, tax_rate_bps, default_unit, updated_at \
     FROM business_settings";

/// Creates or replaces the tenant's settings row and returns the stored result.
/// `tenant_id` is the conflict target (it is the table's primary key), so a
/// repeated `PUT` updates in place rather than erroring or duplicating.
const UPSERT_SETTINGS: &str = "INSERT INTO business_settings \
     (tenant_id, legal_name, tax_code, address, phone, email, logo_url, \
      currency, tax_rate_bps, default_unit) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
     ON CONFLICT (tenant_id) DO UPDATE SET \
       legal_name   = EXCLUDED.legal_name, \
       tax_code     = EXCLUDED.tax_code, \
       address      = EXCLUDED.address, \
       phone        = EXCLUDED.phone, \
       email        = EXCLUDED.email, \
       logo_url     = EXCLUDED.logo_url, \
       currency     = EXCLUDED.currency, \
       tax_rate_bps = EXCLUDED.tax_rate_bps, \
       default_unit = EXCLUDED.default_unit, \
       updated_at   = now() \
     RETURNING legal_name, tax_code, address, phone, email, logo_url, \
               currency, tax_rate_bps, default_unit, updated_at";

/// Why a settings request failed (CLAUDE.md §12). Messages never echo input.
#[derive(Debug, Error)]
pub(crate) enum SettingsError {
    /// The tenant has not saved a configuration yet.
    #[error("business settings not found")]
    NotFound,

    /// A stored row could not be parsed back into the typed config — a data or
    /// programmer error (the DB `CHECK`s should make it impossible), surfaced
    /// as a 500 rather than served as garbage.
    #[error(transparent)]
    Parse(#[from] crate::domain::DomainError),

    /// A database or connection-pool failure.
    #[error(transparent)]
    Db(#[from] db::DbError),

    /// The bounded round-trip exceeded [`limits::SETTINGS_QUERY_TIMEOUT`].
    #[error("settings query timed out")]
    Timeout,
}

impl IntoResponse for SettingsError {
    fn into_response(self) -> Response {
        if matches!(self, Self::NotFound) {
            return StatusCode::NOT_FOUND.into_response();
        }
        // A bounded-query timeout is an availability failure, not an internal
        // bug: report it as 504 so it is distinguishable from a 500. Parse / Db
        // are unexpected → 500. Either way log with the error attached so the
        // OTel bridge marks the span ERROR (CLAUDE.md §2).
        let status = if matches!(self, Self::Timeout) {
            StatusCode::GATEWAY_TIMEOUT
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        tracing::error!(error = ?self, event = "settings.request.failed");
        status.into_response()
    }
}

/// `GET /settings` — the tenant's business configuration, or `404` if unset.
pub(crate) async fn get_settings(
    State(state): State<AppState>,
    principal: AuthPrincipal,
) -> Result<Json<SettingsResponse>, SettingsError> {
    let row = timeout(
        limits::SETTINGS_QUERY_TIMEOUT,
        load_row(&state.db, principal.tenant_id),
    )
    .await
    .map_err(|_| SettingsError::Timeout)??
    .ok_or(SettingsError::NotFound)?;
    Ok(Json(SettingsResponse::try_from(row)?))
}

/// `PUT /settings` — create or replace the tenant's business configuration.
pub(crate) async fn put_settings(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Json(input): Json<BusinessSettings>,
) -> Result<Json<SettingsResponse>, SettingsError> {
    let row = timeout(
        limits::SETTINGS_QUERY_TIMEOUT,
        upsert_row(&state.db, principal.tenant_id, &input),
    )
    .await
    .map_err(|_| SettingsError::Timeout)??;
    Ok(Json(SettingsResponse::try_from(row)?))
}

/// Reads the tenant's settings row inside its RLS context (`None` if unset).
///
/// Takes a `&PgPool` rather than `&AppState` so the SQL + RLS path is exercised
/// directly by the `#[sqlx::test]` suite below.
async fn load_row(
    pool: &PgPool,
    tenant: TenantId,
) -> Result<Option<BusinessSettingsRow>, db::DbError> {
    let mut tx = db::begin_tenant_tx(pool, tenant).await?;
    let row = sqlx::query_as::<_, BusinessSettingsRow>(SELECT_SETTINGS)
        .fetch_optional(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(row)
}

/// Upserts the tenant's settings row inside its RLS context and returns it.
/// All values are bound parameters — never interpolated (CLAUDE.md §10). The
/// `tenant_id` is bound from the resolved scope and re-validated by the RLS
/// `WITH CHECK`, so a row can only ever be written for the caller's tenant.
async fn upsert_row(
    pool: &PgPool,
    tenant: TenantId,
    input: &BusinessSettings,
) -> Result<BusinessSettingsRow, db::DbError> {
    let mut tx = db::begin_tenant_tx(pool, tenant).await?;
    let row = sqlx::query_as::<_, BusinessSettingsRow>(UPSERT_SETTINGS)
        .bind(tenant.as_uuid())
        .bind(input.legal_name.as_str())
        .bind(input.tax_code.as_ref().map(TaxCode::as_str))
        .bind(input.address.as_ref().map(Address::as_str))
        .bind(input.phone.as_ref().map(Phone::as_str))
        .bind(input.email.as_ref().map(EmailAddress::as_str))
        .bind(input.logo_url.as_ref().map(LogoRef::as_str))
        .bind(input.currency.as_str())
        .bind(i32::from(input.tax_rate_bps.get()))
        .bind(input.default_unit.as_str())
        .fetch_one(&mut *tx)
        .await?;
    // Post-conditions: the upsert's RETURNING must echo exactly what we bound
    // (CLAUDE.md §6 — assert immediately after a read with a known shape). A
    // mismatch means the statement's column/EXCLUDED mapping has drifted.
    assert_eq!(
        row.legal_name,
        input.legal_name.as_str(),
        "upsert RETURNING must echo the written legal_name"
    );
    assert_eq!(
        row.tax_rate_bps,
        i32::from(input.tax_rate_bps.get()),
        "upsert RETURNING must echo the written tax_rate_bps"
    );
    tx.commit().await?;
    Ok(row)
}

/// `GET`/`PUT` response: the stored configuration plus when it last changed.
#[derive(Debug, Serialize)]
pub(crate) struct SettingsResponse {
    #[serde(flatten)]
    settings: BusinessSettings,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl TryFrom<BusinessSettingsRow> for SettingsResponse {
    type Error = crate::domain::DomainError;

    fn try_from(row: BusinessSettingsRow) -> Result<Self, Self::Error> {
        // `updated_at` is `Copy`, so read it before the row is consumed by the
        // typed-config conversion.
        let updated_at = row.updated_at;
        let settings = BusinessSettings::try_from(row)?;
        Ok(Self {
            settings,
            updated_at,
        })
    }
}

#[cfg(test)]
mod tests {
    //! Settings persistence and tenant isolation, against real Postgres.
    //!
    //! Uses the shared `crate::db::test_support` harness: `#[sqlx::test]` applies
    //! the embedded migrations as admin, then we connect a pool as the
    //! least-privilege `erp_app` role so the RLS policy is genuinely exercised.

    use super::{BusinessSettings, load_row, upsert_row};
    use crate::db::begin_tenant_tx;
    use crate::db::test_support::{app_pool, migrator, new_tenant, seed_tenant};
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use sqlx::{Connection as _, PgConnection};

    /// A valid settings payload with required fields and one optional set.
    fn sample(legal_name: &str) -> BusinessSettings {
        let json = format!(
            r#"{{ "legal_name": "{legal_name}", "tax_code": "0312345678",
                  "currency": "VND", "tax_rate_bps": 1000, "default_unit": "tờ" }}"#
        );
        serde_json::from_str(&json).expect("sample payload is valid")
    }

    #[sqlx::test]
    async fn upsert_then_load_round_trips(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = app_pool(opts, conn).await;
        let tenant = new_tenant();
        seed_tenant(&pool, tenant, "acme").await;

        upsert_row(&pool, tenant, &sample("Acme Print Co"))
            .await
            .expect("upsert succeeds");
        let row = load_row(&pool, tenant)
            .await
            .expect("load succeeds")
            .expect("a row exists after upsert");

        assert_eq!(row.legal_name, "Acme Print Co");
        assert_eq!(row.currency, "VND");
        assert_eq!(row.tax_rate_bps, 1000);
        assert_eq!(row.default_unit, "tờ");
        assert_eq!(row.tax_code.as_deref(), Some("0312345678"));
    }

    #[sqlx::test]
    async fn second_upsert_updates_in_place(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = app_pool(opts, conn).await;
        let tenant = new_tenant();
        seed_tenant(&pool, tenant, "acme").await;

        upsert_row(&pool, tenant, &sample("First Name"))
            .await
            .expect("first upsert");
        upsert_row(&pool, tenant, &sample("Second Name"))
            .await
            .expect("second upsert");

        // Exactly one row, carrying the latest value (idempotent replace).
        let mut tx = begin_tenant_tx(&pool, tenant).await.expect("begin tx");
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM business_settings")
            .fetch_one(&mut *tx)
            .await
            .expect("count rows");
        assert_eq!(count, 1, "an upsert must not create a second row");

        let row = load_row(&pool, tenant)
            .await
            .expect("load")
            .expect("row exists");
        assert_eq!(row.legal_name, "Second Name", "the latest value wins");
    }

    #[sqlx::test]
    async fn load_is_isolated_per_tenant(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = app_pool(opts, conn).await;
        let (a, b) = (new_tenant(), new_tenant());
        seed_tenant(&pool, a, "tenant-a").await;
        seed_tenant(&pool, b, "tenant-b").await;
        upsert_row(&pool, a, &sample("Tenant A Co"))
            .await
            .expect("seed A settings");

        // B has saved nothing; under RLS it must not see A's row.
        let b_view = load_row(&pool, b).await.expect("load in B's context");
        assert!(
            b_view.is_none(),
            "tenant B must not see tenant A's settings"
        );

        let a_view = load_row(&pool, a)
            .await
            .expect("load in A's context")
            .expect("A sees its own row");
        assert_eq!(a_view.legal_name, "Tenant A Co");
    }

    #[sqlx::test]
    async fn no_tenant_context_denies_all_rows(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = app_pool(opts, conn).await;
        let tenant = new_tenant();
        seed_tenant(&pool, tenant, "acme").await;
        upsert_row(&pool, tenant, &sample("Acme Print Co"))
            .await
            .expect("seed settings");

        // A plain transaction never sets `app.current_tenant`: default-deny.
        let mut tx = pool.begin().await.expect("begin plain tx");
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM business_settings")
            .fetch_one(&mut *tx)
            .await
            .expect("count without context");
        assert_eq!(count, 0, "no tenant context must expose zero rows");
    }

    #[sqlx::test]
    async fn cross_tenant_insert_is_rejected(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = app_pool(opts, conn).await;
        let (a, b) = (new_tenant(), new_tenant());
        seed_tenant(&pool, a, "tenant-a").await;
        seed_tenant(&pool, b, "tenant-b").await;

        // In tenant A's context, try to write a row stamped for tenant B.
        let mut tx = begin_tenant_tx(&pool, a).await.expect("begin tenant tx");
        let result = sqlx::query(
            "INSERT INTO business_settings (tenant_id, legal_name, default_unit) \
             VALUES ($1, $2, $3)",
        )
        .bind(b.as_uuid())
        .bind("Intruder Co")
        .bind("tờ")
        .execute(&mut *tx)
        .await;

        let err = result.expect_err("WITH CHECK must reject a cross-tenant insert");
        assert!(
            err.to_string().contains("row-level security"),
            "rejection must come from the RLS policy, got: {err}"
        );
    }

    #[sqlx::test]
    async fn migration_is_reversible(_opts: PgPoolOptions, conn: PgConnectOptions) {
        // Run as admin (DDL): the table exists after migrate; reverting the
        // settings migration drops it; re-applying restores it (CLAUDE.md §13).
        let mut admin = PgConnection::connect_with(&conn)
            .await
            .expect("admin connection");

        let before: Option<bool> = sqlx::query_scalar(FORCE_RLS_QUERY)
            .fetch_optional(&mut admin)
            .await
            .expect("read forcerowsecurity");
        assert_eq!(
            before,
            Some(true),
            "migration leaves the table with FORCE RLS"
        );

        migrator()
            .undo(&mut admin, PREV_MIGRATION_VERSION)
            .await
            .expect("revert settings migration");
        let after_undo: Option<bool> = sqlx::query_scalar(FORCE_RLS_QUERY)
            .fetch_optional(&mut admin)
            .await
            .expect("read after undo");
        assert_eq!(after_undo, None, "down migration drops the table");

        migrator()
            .run(&mut admin)
            .await
            .expect("re-apply settings migration");
        let again: Option<bool> = sqlx::query_scalar(FORCE_RLS_QUERY)
            .fetch_optional(&mut admin)
            .await
            .expect("read after re-apply");
        assert_eq!(again, Some(true), "re-applied migration restores the table");
    }

    /// Version of the migration *before* business_settings; reverting to it
    /// undoes only the settings migration.
    const PREV_MIGRATION_VERSION: i64 = 20_260_623_000_002;

    /// Reads whether `business_settings` has `FORCE ROW LEVEL SECURITY`. Returns
    /// no row at all once the table has been dropped by the down migration.
    const FORCE_RLS_QUERY: &str =
        "SELECT relforcerowsecurity FROM pg_class WHERE relname = 'business_settings'";
}

#[cfg(test)]
mod boundary_tests {
    //! HTTP-boundary unit tests: status-code mapping and response JSON shape.
    //! These need no database, so they live apart from the `#[sqlx::test]`
    //! integration suite above.
    //!
    //! A full router `GET`/`PUT` round-trip is intentionally not here: the
    //! handlers take `State<AppState>`, whose construction requires a live Redis
    //! connection that `#[sqlx::test]` does not provision. The handler body is
    //! covered by the `load_row`/`upsert_row` RLS tests and the domain serde
    //! tests; this module pins the boundary translation those don't observe.

    use super::{SettingsError, SettingsResponse};
    use crate::domain::{BusinessSettingsRow, DomainError};
    use axum::http::StatusCode;
    use axum::response::IntoResponse as _;

    #[test]
    fn settings_error_maps_to_expected_status() {
        assert_eq!(
            SettingsError::NotFound.into_response().status(),
            StatusCode::NOT_FOUND,
            "an unset config is 404"
        );
        assert_eq!(
            SettingsError::Timeout.into_response().status(),
            StatusCode::GATEWAY_TIMEOUT,
            "a bounded-query timeout is 504, not 500"
        );
        assert_eq!(
            SettingsError::Parse(DomainError::Empty("legal_name"))
                .into_response()
                .status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "an unexpected parse failure is 500"
        );
    }

    #[test]
    fn response_serializes_flat_with_timestamp() {
        let row = BusinessSettingsRow {
            legal_name: "Acme Print Co".to_owned(),
            tax_code: Some("0312345678".to_owned()),
            address: None,
            phone: None,
            email: None,
            logo_url: None,
            currency: "VND".to_owned(),
            tax_rate_bps: 1000,
            default_unit: "tờ".to_owned(),
            updated_at: chrono::DateTime::from_timestamp(1_700_000_000, 0)
                .expect("fixed timestamp is valid"),
        };
        let response = SettingsResponse::try_from(row).expect("a valid row converts");
        let json = serde_json::to_value(&response).expect("response serializes");

        // `settings` is flattened: its fields sit at the top level next to
        // `updated_at`, with no nested "settings" object.
        assert!(
            json.get("settings").is_none(),
            "settings must be flattened, not nested"
        );
        assert_eq!(json["legal_name"], "Acme Print Co");
        assert_eq!(json["currency"], "VND");
        assert_eq!(json["tax_rate_bps"], 1000);
        assert!(
            json.get("address").is_none(),
            "absent optional fields are omitted"
        );
        assert!(
            json["updated_at"]
                .as_str()
                .expect("updated_at serializes as a string")
                .starts_with("2023-11-14T22:13:20"),
            "updated_at renders as an RFC 3339 timestamp"
        );
    }
}
