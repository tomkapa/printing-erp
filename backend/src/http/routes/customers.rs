//! Customer profile routes (CRM, issue #17).
//!
//! Every handler resolves the tenant from the authenticated principal (via the
//! [`Require`] guard, which also enforces the caller's role), runs DB work inside
//! a [`db::begin_tenant_tx`] (so Row-Level Security applies), and bounds every
//! I/O await with a timeout (CLAUDE.md §5). The customer code is system-assigned
//! (`CS001`, …) — never accepted from the request — and removal is a soft archive.

use crate::authz::{DeleteCustomer, ReadCustomer, WriteCustomer};
use crate::crm::limits as crm_limits;
use crate::crm::repo::{CustomerPatch, NewCustomer};
use crate::crm::{CrmError, Customer, CustomerCode, CustomerName, Notes, RecordStatus, repo};
use crate::db;
use crate::domain::{Address, CustomerId, EmailAddress, Phone, TaxCode, TenantId};
use crate::http::Require;
use crate::http::limits as http_limits;
use crate::http::state::AppState;
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use uuid::Uuid;

/// `POST /customers` request: the contact fields a client may set. The code, id,
/// status and timestamps are system-managed and never accepted here.
#[derive(Debug, Deserialize)]
pub(crate) struct CreateCustomerRequest {
    name: CustomerName,
    #[serde(default)]
    tax_code: Option<TaxCode>,
    #[serde(default)]
    address: Option<Address>,
    #[serde(default)]
    phone: Option<Phone>,
    #[serde(default)]
    email: Option<EmailAddress>,
    #[serde(default)]
    notes: Option<Notes>,
}

/// `PATCH /customers/{id}` request: every field optional, but at least one must
/// be present (an empty patch is `422`). Absent fields are left untouched.
#[derive(Debug, Deserialize)]
pub(crate) struct UpdateCustomerRequest {
    #[serde(default)]
    name: Option<CustomerName>,
    #[serde(default)]
    tax_code: Option<TaxCode>,
    #[serde(default)]
    address: Option<Address>,
    #[serde(default)]
    phone: Option<Phone>,
    #[serde(default)]
    email: Option<EmailAddress>,
    #[serde(default)]
    notes: Option<Notes>,
}

impl UpdateCustomerRequest {
    /// True when the patch carries no updatable field.
    const fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.tax_code.is_none()
            && self.address.is_none()
            && self.phone.is_none()
            && self.email.is_none()
            && self.notes.is_none()
    }
}

/// `GET /customers` query parameters.
#[derive(Debug, Deserialize)]
pub(crate) struct ListQuery {
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
    /// `active` (default) or `archived`.
    #[serde(default)]
    status: Option<String>,
    /// Case-insensitive name substring filter.
    #[serde(default)]
    q: Option<String>,
}

/// Public view of a customer. `None` optionals are omitted from the JSON.
#[derive(Debug, Serialize)]
pub(crate) struct CustomerView {
    id: CustomerId,
    code: CustomerCode,
    name: CustomerName,
    #[serde(skip_serializing_if = "Option::is_none")]
    tax_code: Option<TaxCode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    phone: Option<Phone>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<EmailAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<Notes>,
    status: RecordStatus,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// `POST /customers` — create a customer with a freshly-allocated code.
pub(crate) async fn create(
    State(state): State<AppState>,
    guard: Require<WriteCustomer>,
    Json(request): Json<CreateCustomerRequest>,
) -> Result<(StatusCode, Json<CustomerView>), CrmError> {
    let tenant = guard.principal.tenant_id;
    let new = NewCustomer {
        name: &request.name,
        tax_code: request.tax_code.as_ref(),
        address: request.address.as_ref(),
        phone: request.phone.as_ref(),
        email: request.email.as_ref(),
        notes: request.notes.as_ref(),
    };
    let work = async {
        let mut tx = db::begin_tenant_tx(&state.db, tenant).await?;
        let customer = repo::insert_customer(&mut tx, tenant, &new).await?;
        tx.commit().await?;
        Ok::<Customer, CrmError>(customer)
    };
    let customer = timeout(http_limits::TENANT_QUERY_TIMEOUT, work).await??;
    Ok((StatusCode::CREATED, Json(view_of(customer))))
}

/// `GET /customers` — list this tenant's customers, filtered and paginated.
pub(crate) async fn list(
    State(state): State<AppState>,
    guard: Require<ReadCustomer>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<CustomerView>>, CrmError> {
    let tenant = guard.principal.tenant_id;
    let status = parse_status(query.status.as_deref())?;
    let limit = clamp_limit(query.limit);
    let offset = query
        .offset
        .unwrap_or(0)
        .clamp(0, crm_limits::MAX_CUSTOMERS_OFFSET);
    let needle = search_needle(query.q.as_deref());

    let work = async {
        let mut tx = db::begin_tenant_tx(&state.db, tenant).await?;
        let customers = repo::list_customers(&mut tx, status, needle, limit, offset).await?;
        tx.commit().await?;
        Ok::<Vec<Customer>, CrmError>(customers)
    };
    let customers = timeout(http_limits::TENANT_QUERY_TIMEOUT, work).await??;
    Ok(Json(customers.into_iter().map(view_of).collect()))
}

/// `GET /customers/{id}` — fetch one active customer.
pub(crate) async fn get_one(
    State(state): State<AppState>,
    guard: Require<ReadCustomer>,
    Path(id): Path<Uuid>,
) -> Result<Json<CustomerView>, CrmError> {
    let tenant = guard.principal.tenant_id;
    let customer = CustomerId::try_from(id)?;
    let fetched = fetch(&state, tenant, customer).await?;
    Ok(Json(view_of(fetched)))
}

/// `PATCH /customers/{id}` — partial update of a customer's fields.
pub(crate) async fn update(
    State(state): State<AppState>,
    guard: Require<WriteCustomer>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateCustomerRequest>,
) -> Result<Json<CustomerView>, CrmError> {
    let tenant = guard.principal.tenant_id;
    if request.is_empty() {
        return Err(CrmError::EmptyPatch);
    }
    let customer = CustomerId::try_from(id)?;
    let patch = CustomerPatch {
        name: request.name.as_ref(),
        tax_code: request.tax_code.as_ref(),
        address: request.address.as_ref(),
        phone: request.phone.as_ref(),
        email: request.email.as_ref(),
        notes: request.notes.as_ref(),
    };
    let work = async {
        let mut tx = db::begin_tenant_tx(&state.db, tenant).await?;
        let updated = repo::patch_customer(&mut tx, customer, &patch).await?;
        tx.commit().await?;
        Ok::<Customer, CrmError>(updated)
    };
    let updated = timeout(http_limits::TENANT_QUERY_TIMEOUT, work).await??;
    Ok(Json(view_of(updated)))
}

/// `DELETE /customers/{id}` — soft-archive a customer (404 if already gone).
pub(crate) async fn delete(
    State(state): State<AppState>,
    guard: Require<DeleteCustomer>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, CrmError> {
    let tenant = guard.principal.tenant_id;
    let customer = CustomerId::try_from(id)?;
    let work = async {
        let mut tx = db::begin_tenant_tx(&state.db, tenant).await?;
        repo::archive_customer(&mut tx, customer).await?;
        tx.commit().await?;
        Ok::<(), CrmError>(())
    };
    timeout(http_limits::TENANT_QUERY_TIMEOUT, work).await??;
    Ok(StatusCode::NO_CONTENT)
}

/// Fetches one active customer inside a bounded tenant transaction.
async fn fetch(
    state: &AppState,
    tenant: TenantId,
    customer: CustomerId,
) -> Result<Customer, CrmError> {
    let work = async {
        let mut tx = db::begin_tenant_tx(&state.db, tenant).await?;
        let customer = repo::get_customer(&mut tx, tenant, customer).await?;
        tx.commit().await?;
        Ok::<Customer, CrmError>(customer)
    };
    timeout(http_limits::TENANT_QUERY_TIMEOUT, work).await?
}

/// Parses the `?status=` filter; absent means `active`. An unknown value is a
/// client error (`400`).
fn parse_status(raw: Option<&str>) -> Result<RecordStatus, CrmError> {
    raw.map_or(Ok(RecordStatus::Active), |value| {
        RecordStatus::try_from(value).map_err(|_| CrmError::InvalidQuery)
    })
}

/// Trims the optional `?q=` name filter and bounds it to a char boundary within
/// [`crm_limits::MAX_CUSTOMER_SEARCH`] (CLAUDE.md §5), borrowing a sub-slice
/// rather than allocating. An empty needle means "no filter" (`None`).
fn search_needle(raw: Option<&str>) -> Option<&str> {
    let trimmed = raw.map(str::trim).filter(|s| !s.is_empty())?;
    let end = trimmed
        .char_indices()
        .nth(crm_limits::MAX_CUSTOMER_SEARCH)
        .map_or(trimmed.len(), |(index, _)| index);
    Some(&trimmed[..end])
}

/// Clamps a requested page size into `1..=MAX_CUSTOMERS_PER_PAGE`, defaulting when
/// absent or non-positive — so [`repo::list_customers`]'s entry assertions hold.
fn clamp_limit(requested: Option<i64>) -> i64 {
    match requested {
        Some(n) if n > 0 => n.min(crm_limits::MAX_CUSTOMERS_PER_PAGE),
        _ => crm_limits::DEFAULT_CUSTOMERS_PER_PAGE,
    }
}

/// Projects a stored [`Customer`] into its public view, consuming it.
fn view_of(customer: Customer) -> CustomerView {
    CustomerView {
        id: customer.id,
        code: customer.code,
        name: customer.name,
        tax_code: customer.tax_code,
        address: customer.address,
        phone: customer.phone,
        email: customer.email,
        notes: customer.notes,
        status: customer.status,
        created_at: customer.created_at,
        updated_at: customer.updated_at,
    }
}

#[cfg(test)]
mod tests {
    //! End-to-end `/customers` tests: the full router + `Require` guard over a
    //! tenant transaction against real Postgres (CLAUDE.md §3). Requests carry a
    //! real Bearer access token minted from the test auth context.

    use crate::domain::{Role, TenantId, UserId};
    use crate::http::AppState;
    use crate::testsupport;
    use crate::testsupport::{bearer, send};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

    async fn setup(opts: PgPoolOptions, conn: PgConnectOptions) -> (AppState, UserId, TenantId) {
        let pool = testsupport::app_pool(opts, conn).await;
        let tenant = testsupport::new_tenant();
        testsupport::seed_tenant(&pool, tenant, "acme").await;
        let user =
            testsupport::seed_user(&pool, tenant, "u@acme.test", Role::Admin, "x", true).await;
        let state =
            testsupport::app_state(pool, testsupport::test_clock(), testsupport::auth_context())
                .await;
        (state, user, tenant)
    }

    fn json_request(
        method: &str,
        uri: &str,
        bearer: &str,
        body: &serde_json::Value,
    ) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", bearer)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("build request")
    }

    fn request(method: &str, uri: &str, bearer: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", bearer)
            .body(Body::empty())
            .expect("build request")
    }

    fn create_body(name: &str) -> serde_json::Value {
        serde_json::json!({ "name": name, "phone": "0900-000-000" })
    }

    /// Creates a customer as admin and returns its id string.
    async fn create_customer(state: &AppState, admin: &str, name: &str) -> String {
        let (status, body) = send(
            state,
            json_request("POST", "/api/customers", admin, &create_body(name)),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "admin creates a customer");
        body["id"].as_str().expect("id string").to_owned()
    }

    #[sqlx::test]
    async fn create_assigns_code_and_is_listable(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (state, user, tenant) = setup(opts, conn).await;
        let admin = bearer(&state, user, tenant, Role::Admin);

        let (status, body) = send(
            &state,
            json_request("POST", "/api/customers", &admin, &create_body("Acme")),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["code"], "CS001", "first customer is CS001");
        assert_eq!(body["name"], "Acme");
        assert_eq!(body["status"], "active");

        // A second customer gets the next sequential code.
        let (_, body2) = send(
            &state,
            json_request("POST", "/api/customers", &admin, &create_body("Beta")),
        )
        .await;
        assert_eq!(body2["code"], "CS002");

        let (list_status, list) = send(&state, request("GET", "/api/customers", &admin)).await;
        assert_eq!(list_status, StatusCode::OK);
        assert_eq!(list.as_array().map(Vec::len), Some(2));
    }

    #[sqlx::test]
    async fn create_rejects_blank_name(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (state, user, tenant) = setup(opts, conn).await;
        let admin = bearer(&state, user, tenant, Role::Admin);
        let (status, _) = send(
            &state,
            json_request(
                "POST",
                "/api/customers",
                &admin,
                &serde_json::json!({ "name": "  " }),
            ),
        )
        .await;
        // The `CustomerName` newtype rejects it during JSON deserialization.
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[sqlx::test]
    async fn get_returns_customer_then_404_after_archive(
        opts: PgPoolOptions,
        conn: PgConnectOptions,
    ) {
        let (state, user, tenant) = setup(opts, conn).await;
        let admin = bearer(&state, user, tenant, Role::Admin);
        let id = create_customer(&state, &admin, "Acme").await;

        let (status, body) = send(
            &state,
            request("GET", &format!("/api/customers/{id}"), &admin),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["id"], id);

        let (del, _) = send(
            &state,
            request("DELETE", &format!("/api/customers/{id}"), &admin),
        )
        .await;
        assert_eq!(del, StatusCode::NO_CONTENT);
        let (after, _) = send(
            &state,
            request("GET", &format!("/api/customers/{id}"), &admin),
        )
        .await;
        assert_eq!(after, StatusCode::NOT_FOUND, "archived customer is gone");
        // A second archive is also a 404 (the active row is no longer there).
        let (twice, _) = send(
            &state,
            request("DELETE", &format!("/api/customers/{id}"), &admin),
        )
        .await;
        assert_eq!(twice, StatusCode::NOT_FOUND);
    }

    #[sqlx::test]
    async fn archived_filter_lists_archived(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (state, user, tenant) = setup(opts, conn).await;
        let admin = bearer(&state, user, tenant, Role::Admin);
        let id = create_customer(&state, &admin, "Acme").await;
        send(
            &state,
            request("DELETE", &format!("/api/customers/{id}"), &admin),
        )
        .await;

        let (status, active) = send(&state, request("GET", "/api/customers", &admin)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            active.as_array().map(Vec::len),
            Some(0),
            "default is active-only"
        );
        let (_, archived) = send(
            &state,
            request("GET", "/api/customers?status=archived", &admin),
        )
        .await;
        assert_eq!(archived.as_array().map(Vec::len), Some(1));
    }

    #[sqlx::test]
    async fn patch_updates_fields_and_empty_patch_is_422(
        opts: PgPoolOptions,
        conn: PgConnectOptions,
    ) {
        let (state, user, tenant) = setup(opts, conn).await;
        let admin = bearer(&state, user, tenant, Role::Admin);
        let id = create_customer(&state, &admin, "Old").await;

        let (status, body) = send(
            &state,
            json_request(
                "PATCH",
                &format!("/api/customers/{id}"),
                &admin,
                &serde_json::json!({"name": "New"}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["name"], "New");
        assert_eq!(body["code"], "CS001", "code is immutable");

        let (empty, _) = send(
            &state,
            json_request(
                "PATCH",
                &format!("/api/customers/{id}"),
                &admin,
                &serde_json::json!({}),
            ),
        )
        .await;
        assert_eq!(
            empty,
            StatusCode::UNPROCESSABLE_ENTITY,
            "empty patch rejected"
        );
    }

    #[sqlx::test]
    async fn list_is_tenant_isolated(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (state, user_a, tenant_a) = setup(opts, conn).await;
        let admin_a = bearer(&state, user_a, tenant_a, Role::Admin);
        create_customer(&state, &admin_a, "A Co").await;

        let tenant_b = testsupport::new_tenant();
        testsupport::seed_tenant(&state.db, tenant_b, "beta").await;
        let user_b =
            testsupport::seed_user(&state.db, tenant_b, "b@beta.test", Role::Admin, "x", true)
                .await;
        let admin_b = bearer(&state, user_b, tenant_b, Role::Admin);

        let (status, list) = send(&state, request("GET", "/api/customers", &admin_b)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            list.as_array().map(Vec::len),
            Some(0),
            "tenant B never sees tenant A's customers"
        );
    }

    #[sqlx::test]
    async fn missing_bearer_is_401(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (state, _user, _tenant) = setup(opts, conn).await;
        let req = Request::builder()
            .uri("/api/customers")
            .body(Body::empty())
            .expect("build request");
        let (status, _) = send(&state, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}

#[cfg(test)]
mod authz_tests {
    //! RBAC matrix for `/customers` (issue #17): reads are open to every role;
    //! `WriteCustomer` is admin/sales/coordinator; `DeleteCustomer` is
    //! admin/coordinator. The guard reads the token's role claim, so one seeded
    //! user acts as any role.

    use crate::domain::{Role, TenantId, UserId};
    use crate::http::AppState;
    use crate::testsupport;
    use crate::testsupport::{bearer, send};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

    async fn setup(opts: PgPoolOptions, conn: PgConnectOptions) -> (AppState, UserId, TenantId) {
        let pool = testsupport::app_pool(opts, conn).await;
        let tenant = testsupport::new_tenant();
        testsupport::seed_tenant(&pool, tenant, "acme").await;
        let user =
            testsupport::seed_user(&pool, tenant, "u@acme.test", Role::Admin, "x", true).await;
        let state =
            testsupport::app_state(pool, testsupport::test_clock(), testsupport::auth_context())
                .await;
        (state, user, tenant)
    }

    fn post_create(bearer: &str) -> Request<Body> {
        let body = serde_json::json!({ "name": "Acme" });
        Request::builder()
            .method("POST")
            .uri("/api/customers")
            .header("authorization", bearer)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("build POST")
    }

    fn request(method: &str, uri: &str, bearer: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", bearer)
            .body(Body::empty())
            .expect("build request")
    }

    async fn create_as_admin(state: &AppState, user: UserId, tenant: TenantId) -> String {
        let admin = bearer(state, user, tenant, Role::Admin);
        let (status, body) = send(state, post_create(&admin)).await;
        assert_eq!(status, StatusCode::CREATED);
        body["id"].as_str().expect("id").to_owned()
    }

    #[sqlx::test]
    async fn read_is_open_to_every_role(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (state, user, tenant) = setup(opts, conn).await;
        for role in [
            Role::Admin,
            Role::Sales,
            Role::Coordinator,
            Role::Scheduler,
            Role::Operator,
        ] {
            let token = bearer(&state, user, tenant, role);
            let (status, _) = send(&state, request("GET", "/api/customers", &token)).await;
            assert_eq!(status, StatusCode::OK, "role {role:?} may list customers");
        }
    }

    #[sqlx::test]
    async fn write_is_admin_sales_coordinator(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (state, user, tenant) = setup(opts, conn).await;
        for role in [Role::Admin, Role::Sales, Role::Coordinator] {
            let token = bearer(&state, user, tenant, role);
            let (status, _) = send(&state, post_create(&token)).await;
            assert_eq!(status, StatusCode::CREATED, "role {role:?} may create");
        }
        for role in [Role::Scheduler, Role::Operator] {
            let token = bearer(&state, user, tenant, role);
            let (status, _) = send(&state, post_create(&token)).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "role {role:?} may not create"
            );
        }
    }

    #[sqlx::test]
    async fn delete_is_admin_coordinator_only(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (state, user, tenant) = setup(opts, conn).await;

        for role in [Role::Sales, Role::Scheduler, Role::Operator] {
            let id = create_as_admin(&state, user, tenant).await;
            let token = bearer(&state, user, tenant, role);
            let (status, _) = send(
                &state,
                request("DELETE", &format!("/api/customers/{id}"), &token),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "role {role:?} may not archive"
            );
        }

        let id = create_as_admin(&state, user, tenant).await;
        let coordinator = bearer(&state, user, tenant, Role::Coordinator);
        let (status, _) = send(
            &state,
            request("DELETE", &format!("/api/customers/{id}"), &coordinator),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "coordinator may archive");
    }
}
