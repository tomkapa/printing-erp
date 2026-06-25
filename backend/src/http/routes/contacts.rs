//! Contact routes (CRM, issue #17): people attached to a customer.
//!
//! Contacts are a sub-resource of a customer and share its capabilities
//! ([`WriteCustomer`]/[`ReadCustomer`]/[`DeleteCustomer`]). Creating or listing
//! contacts first resolves the parent customer inside the tenant transaction, so
//! a missing/archived/cross-tenant customer is a clean `404` (and the composite
//! FK structurally prevents a contact ever pointing across tenants). Every I/O
//! await is bounded (CLAUDE.md §5).

use crate::authz::{DeleteCustomer, ReadCustomer, WriteCustomer};
use crate::crm::repo::{ContactPatch, NewContact};
use crate::crm::{Contact, ContactName, ContactTitle, CrmError, RecordStatus, repo};
use crate::db;
use crate::domain::{ContactId, CustomerId, EmailAddress, Phone};
use crate::http::Require;
use crate::http::limits as http_limits;
use crate::http::state::AppState;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use uuid::Uuid;

/// `POST /customers/{customer_id}/contacts` request.
#[derive(Debug, Deserialize)]
pub(crate) struct CreateContactRequest {
    name: ContactName,
    #[serde(default)]
    title: Option<ContactTitle>,
    #[serde(default)]
    email: Option<EmailAddress>,
    #[serde(default)]
    phone: Option<Phone>,
    #[serde(default)]
    is_primary: bool,
}

/// `PATCH /contacts/{id}` request: every field optional, at least one required.
#[derive(Debug, Deserialize)]
pub(crate) struct UpdateContactRequest {
    #[serde(default)]
    name: Option<ContactName>,
    #[serde(default)]
    title: Option<ContactTitle>,
    #[serde(default)]
    email: Option<EmailAddress>,
    #[serde(default)]
    phone: Option<Phone>,
    #[serde(default)]
    is_primary: Option<bool>,
}

impl UpdateContactRequest {
    /// True when the patch carries no updatable field.
    const fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.title.is_none()
            && self.email.is_none()
            && self.phone.is_none()
            && self.is_primary.is_none()
    }
}

/// Public view of a contact. `None` optionals are omitted from the JSON.
#[derive(Debug, Serialize)]
pub(crate) struct ContactView {
    id: ContactId,
    customer_id: CustomerId,
    name: ContactName,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<ContactTitle>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<EmailAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    phone: Option<Phone>,
    is_primary: bool,
    status: RecordStatus,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// `POST /customers/{customer_id}/contacts` — add a contact to a customer.
pub(crate) async fn create(
    State(state): State<AppState>,
    guard: Require<WriteCustomer>,
    Path(customer_id): Path<Uuid>,
    Json(request): Json<CreateContactRequest>,
) -> Result<(StatusCode, Json<ContactView>), CrmError> {
    let tenant = guard.principal.tenant_id;
    let customer = CustomerId::try_from(customer_id)?;
    let new = NewContact {
        name: &request.name,
        title: request.title.as_ref(),
        email: request.email.as_ref(),
        phone: request.phone.as_ref(),
        is_primary: request.is_primary,
    };
    let work = async {
        let mut tx = db::begin_tenant_tx(&state.db, tenant).await?;
        // Lock the parent active row first: a missing/archived customer is a 404,
        // and the `FOR SHARE` lock blocks a concurrent archive until this insert
        // commits, so the contact can never land active under an archived parent.
        repo::lock_active_customer(&mut tx, customer).await?;
        let contact = repo::insert_contact(&mut tx, tenant, customer, &new).await?;
        tx.commit().await?;
        Ok::<Contact, CrmError>(contact)
    };
    let contact = timeout(http_limits::TENANT_QUERY_TIMEOUT, work).await??;
    Ok((StatusCode::CREATED, Json(view_of(contact))))
}

/// `GET /customers/{customer_id}/contacts` — list a customer's active contacts.
pub(crate) async fn list(
    State(state): State<AppState>,
    guard: Require<ReadCustomer>,
    Path(customer_id): Path<Uuid>,
) -> Result<Json<Vec<ContactView>>, CrmError> {
    let tenant = guard.principal.tenant_id;
    let customer = CustomerId::try_from(customer_id)?;
    let work = async {
        let mut tx = db::begin_tenant_tx(&state.db, tenant).await?;
        repo::get_customer(&mut tx, tenant, customer).await?;
        let contacts = repo::list_contacts(&mut tx, customer).await?;
        tx.commit().await?;
        Ok::<Vec<Contact>, CrmError>(contacts)
    };
    let contacts = timeout(http_limits::TENANT_QUERY_TIMEOUT, work).await??;
    Ok(Json(contacts.into_iter().map(view_of).collect()))
}

/// `PATCH /contacts/{id}` — partial update of a contact's fields.
pub(crate) async fn update(
    State(state): State<AppState>,
    guard: Require<WriteCustomer>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateContactRequest>,
) -> Result<Json<ContactView>, CrmError> {
    let tenant = guard.principal.tenant_id;
    if request.is_empty() {
        return Err(CrmError::EmptyPatch);
    }
    let contact = ContactId::try_from(id)?;
    let patch = ContactPatch {
        name: request.name.as_ref(),
        title: request.title.as_ref(),
        email: request.email.as_ref(),
        phone: request.phone.as_ref(),
        is_primary: request.is_primary,
    };
    let work = async {
        let mut tx = db::begin_tenant_tx(&state.db, tenant).await?;
        let updated = repo::patch_contact(&mut tx, contact, &patch).await?;
        tx.commit().await?;
        Ok::<Contact, CrmError>(updated)
    };
    let updated = timeout(http_limits::TENANT_QUERY_TIMEOUT, work).await??;
    Ok(Json(view_of(updated)))
}

/// `DELETE /contacts/{id}` — soft-archive a contact (404 if already gone).
pub(crate) async fn delete(
    State(state): State<AppState>,
    guard: Require<DeleteCustomer>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, CrmError> {
    let tenant = guard.principal.tenant_id;
    let contact = ContactId::try_from(id)?;
    let work = async {
        let mut tx = db::begin_tenant_tx(&state.db, tenant).await?;
        repo::archive_contact(&mut tx, contact).await?;
        tx.commit().await?;
        Ok::<(), CrmError>(())
    };
    timeout(http_limits::TENANT_QUERY_TIMEOUT, work).await??;
    Ok(StatusCode::NO_CONTENT)
}

/// Projects a stored [`Contact`] into its public view, consuming it.
fn view_of(contact: Contact) -> ContactView {
    ContactView {
        id: contact.id,
        customer_id: contact.customer_id,
        name: contact.name,
        title: contact.title,
        email: contact.email,
        phone: contact.phone,
        is_primary: contact.is_primary,
        status: contact.status,
        created_at: contact.created_at,
        updated_at: contact.updated_at,
    }
}

#[cfg(test)]
mod tests {
    //! End-to-end `/contacts` tests over the full router + `Require` guard against
    //! real Postgres (CLAUDE.md §3).

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

    /// Creates a customer and returns its id string.
    async fn create_customer(state: &AppState, admin: &str) -> String {
        let (status, body) = send(
            state,
            json_request(
                "POST",
                "/api/customers",
                admin,
                &serde_json::json!({ "name": "Acme" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        body["id"].as_str().expect("id").to_owned()
    }

    #[sqlx::test]
    async fn create_then_list_contacts(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (state, user, tenant) = setup(opts, conn).await;
        let admin = bearer(&state, user, tenant, Role::Admin);
        let customer = create_customer(&state, &admin).await;

        let body = serde_json::json!({
            "name": "Nguyễn Văn A",
            "title": "Trưởng phòng mua hàng",
            "is_primary": true,
        });
        let (status, contact) = send(
            &state,
            json_request(
                "POST",
                &format!("/api/customers/{customer}/contacts"),
                &admin,
                &body,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(contact["name"], "Nguyễn Văn A");
        assert_eq!(contact["is_primary"], true);
        assert_eq!(contact["customer_id"], customer);

        let (list_status, list) = send(
            &state,
            request(
                "GET",
                &format!("/api/customers/{customer}/contacts"),
                &admin,
            ),
        )
        .await;
        assert_eq!(list_status, StatusCode::OK);
        assert_eq!(list.as_array().map(Vec::len), Some(1));
    }

    #[sqlx::test]
    async fn create_contact_under_missing_customer_is_404(
        opts: PgPoolOptions,
        conn: PgConnectOptions,
    ) {
        let (state, user, tenant) = setup(opts, conn).await;
        let admin = bearer(&state, user, tenant, Role::Admin);
        let missing = uuid::Uuid::new_v4();
        let (status, _) = send(
            &state,
            json_request(
                "POST",
                &format!("/api/customers/{missing}/contacts"),
                &admin,
                &serde_json::json!({ "name": "Ghost" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[sqlx::test]
    async fn create_contact_under_archived_customer_is_404(
        opts: PgPoolOptions,
        conn: PgConnectOptions,
    ) {
        let (state, user, tenant) = setup(opts, conn).await;
        let admin = bearer(&state, user, tenant, Role::Admin);
        let customer = create_customer(&state, &admin).await;
        send(
            &state,
            request("DELETE", &format!("/api/customers/{customer}"), &admin),
        )
        .await;

        let (status, _) = send(
            &state,
            json_request(
                "POST",
                &format!("/api/customers/{customer}/contacts"),
                &admin,
                &serde_json::json!({ "name": "Too Late" }),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "no contacts on an archived customer"
        );
    }

    #[sqlx::test]
    async fn patch_and_archive_contact(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (state, user, tenant) = setup(opts, conn).await;
        let admin = bearer(&state, user, tenant, Role::Admin);
        let customer = create_customer(&state, &admin).await;
        let (_, contact) = send(
            &state,
            json_request(
                "POST",
                &format!("/api/customers/{customer}/contacts"),
                &admin,
                &serde_json::json!({ "name": "Alice" }),
            ),
        )
        .await;
        let id = contact["id"].as_str().expect("id").to_owned();

        let (status, updated) = send(
            &state,
            json_request(
                "PATCH",
                &format!("/api/contacts/{id}"),
                &admin,
                &serde_json::json!({"title": "Director"}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(updated["title"], "Director");
        assert_eq!(updated["name"], "Alice", "name untouched");

        let (empty, _) = send(
            &state,
            json_request(
                "PATCH",
                &format!("/api/contacts/{id}"),
                &admin,
                &serde_json::json!({}),
            ),
        )
        .await;
        assert_eq!(empty, StatusCode::UNPROCESSABLE_ENTITY);

        let (del, _) = send(
            &state,
            request("DELETE", &format!("/api/contacts/{id}"), &admin),
        )
        .await;
        assert_eq!(del, StatusCode::NO_CONTENT);
        let (list_status, list) = send(
            &state,
            request(
                "GET",
                &format!("/api/customers/{customer}/contacts"),
                &admin,
            ),
        )
        .await;
        assert_eq!(list_status, StatusCode::OK);
        assert_eq!(
            list.as_array().map(Vec::len),
            Some(0),
            "archived contact hidden"
        );
    }

    #[sqlx::test]
    async fn contact_write_requires_write_capability(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (state, user, tenant) = setup(opts, conn).await;
        let admin = bearer(&state, user, tenant, Role::Admin);
        let customer = create_customer(&state, &admin).await;

        // Operator may read contacts but not create them.
        let operator = bearer(&state, user, tenant, Role::Operator);
        let (read, _) = send(
            &state,
            request(
                "GET",
                &format!("/api/customers/{customer}/contacts"),
                &operator,
            ),
        )
        .await;
        assert_eq!(read, StatusCode::OK, "operator may read contacts");
        let (write, _) = send(
            &state,
            json_request(
                "POST",
                &format!("/api/customers/{customer}/contacts"),
                &operator,
                &serde_json::json!({ "name": "Nope" }),
            ),
        )
        .await;
        assert_eq!(
            write,
            StatusCode::FORBIDDEN,
            "operator may not create contacts"
        );
    }
}
