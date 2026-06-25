//! Tenant-scoped persistence for [`Customer`] and [`Contact`] rows.
//!
//! Every function runs on a connection already inside a tenant transaction
//! (`db::begin_tenant_tx`), so Row-Level Security scopes all reads and writes to
//! the active tenant. Queries use bound parameters only — never string
//! interpolation (CLAUDE.md §10) — and each `SELECT`/`RETURNING` lists its
//! columns as a fixed literal so [`Customer::try_from`]/[`Contact::try_from`]
//! decode a known shape.

use crate::crm::error::CrmError;
use crate::crm::limits;
use crate::crm::model::{
    Contact, ContactName, ContactTitle, Customer, CustomerCode, CustomerName, Notes, RecordStatus,
};
use crate::domain::{Address, ContactId, CustomerId, EmailAddress, Phone, TaxCode, TenantId};
use sqlx::PgConnection;

/// Fields for a new customer (everything but the system-assigned code/id/status).
#[derive(Debug)]
pub(crate) struct NewCustomer<'a> {
    pub(crate) name: &'a CustomerName,
    pub(crate) tax_code: Option<&'a TaxCode>,
    pub(crate) address: Option<&'a Address>,
    pub(crate) phone: Option<&'a Phone>,
    pub(crate) email: Option<&'a EmailAddress>,
    pub(crate) notes: Option<&'a Notes>,
}

/// Partial update of a customer — every field optional; `None` leaves it as-is.
#[derive(Debug)]
pub(crate) struct CustomerPatch<'a> {
    pub(crate) name: Option<&'a CustomerName>,
    pub(crate) tax_code: Option<&'a TaxCode>,
    pub(crate) address: Option<&'a Address>,
    pub(crate) phone: Option<&'a Phone>,
    pub(crate) email: Option<&'a EmailAddress>,
    pub(crate) notes: Option<&'a Notes>,
}

/// Fields for a new contact attached to a customer.
#[derive(Debug)]
pub(crate) struct NewContact<'a> {
    pub(crate) name: &'a ContactName,
    pub(crate) title: Option<&'a ContactTitle>,
    pub(crate) email: Option<&'a EmailAddress>,
    pub(crate) phone: Option<&'a Phone>,
    pub(crate) is_primary: bool,
}

/// Partial update of a contact — every field optional; `None` leaves it as-is.
#[derive(Debug)]
pub(crate) struct ContactPatch<'a> {
    pub(crate) name: Option<&'a ContactName>,
    pub(crate) title: Option<&'a ContactTitle>,
    pub(crate) email: Option<&'a EmailAddress>,
    pub(crate) phone: Option<&'a Phone>,
    pub(crate) is_primary: Option<bool>,
}

/// Allocates the next per-tenant customer sequence atomically.
///
/// The `ON CONFLICT DO UPDATE` row-locks the counter, so concurrent allocations
/// for one tenant serialize; sharing the caller's transaction means a rolled-back
/// insert rolls back the increment too — gap-free, never a duplicate code.
async fn allocate_seq(conn: &mut PgConnection, tenant: TenantId) -> Result<i64, CrmError> {
    let seq: i64 = sqlx::query_scalar(
        "INSERT INTO customer_code_seq (tenant_id, next_seq) VALUES ($1, 1) \
         ON CONFLICT (tenant_id) DO UPDATE SET next_seq = customer_code_seq.next_seq + 1 \
         RETURNING next_seq",
    )
    .bind(tenant.as_uuid())
    .fetch_one(conn)
    .await?;
    assert!(seq > 0, "allocated sequence is 1-based and positive");
    Ok(seq)
}

/// Inserts a new active customer, assigning the next per-tenant `CS###` code.
///
/// # Errors
///
/// [`CrmError::Db`] on query failure.
pub(crate) async fn insert_customer(
    conn: &mut PgConnection,
    tenant: TenantId,
    new: &NewCustomer<'_>,
) -> Result<Customer, CrmError> {
    let seq = allocate_seq(conn, tenant).await?;
    let code = CustomerCode::from_seq(seq);
    let row = sqlx::query(
        "INSERT INTO customers \
         (tenant_id, code, name, tax_code, address, phone, email, notes) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         RETURNING id, tenant_id, code, name, tax_code, address, phone, email, notes, \
                   status, created_at, updated_at",
    )
    .bind(tenant.as_uuid())
    .bind(code.as_str())
    .bind(new.name.as_str())
    .bind(new.tax_code.map(TaxCode::as_str))
    .bind(new.address.map(Address::as_str))
    .bind(new.phone.map(Phone::as_str))
    .bind(new.email.map(EmailAddress::as_str))
    .bind(new.notes.map(Notes::as_str))
    .fetch_one(conn)
    .await?;
    let customer = Customer::try_from(&row)?;
    assert_eq!(customer.code, code, "stored code echoes the allocated one");
    assert_eq!(
        customer.tenant_id, tenant,
        "row belongs to the active tenant"
    );
    Ok(customer)
}

/// Fetches a non-archived customer by id within the tenant scope.
///
/// # Errors
///
/// [`CrmError::NotFound`] if no visible, active customer has that id.
pub(crate) async fn get_customer(
    conn: &mut PgConnection,
    tenant: TenantId,
    customer: CustomerId,
) -> Result<Customer, CrmError> {
    let row = sqlx::query(
        "SELECT id, tenant_id, code, name, tax_code, address, phone, email, notes, \
                status, created_at, updated_at \
         FROM customers WHERE id = $1 AND status <> 'archived'",
    )
    .bind(customer.as_uuid())
    .fetch_optional(conn)
    .await?
    .ok_or(CrmError::NotFound)?;
    let parsed = Customer::try_from(&row)?;
    assert_eq!(
        parsed.tenant_id, tenant,
        "RLS invariant: a visible row belongs to the active tenant"
    );
    Ok(parsed)
}

/// Lists customers in the tenant scope filtered by `status`, optionally narrowed
/// by a case-insensitive name substring `needle`, newest first.
///
/// `limit`/`offset` are clamped by the caller; the returned vector is bounded by
/// `limit` (CLAUDE.md §5). `needle` is bound, never interpolated (§10).
///
/// # Errors
///
/// [`CrmError::Db`] on query/decode failure.
pub(crate) async fn list_customers(
    conn: &mut PgConnection,
    status: RecordStatus,
    needle: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<Customer>, CrmError> {
    assert!(limit > 0, "page limit must be positive");
    assert!(
        limit <= limits::MAX_CUSTOMERS_PER_PAGE,
        "page limit must be clamped before query"
    );
    assert!(offset >= 0, "page offset must be non-negative");

    let rows = sqlx::query(
        "SELECT id, tenant_id, code, name, tax_code, address, phone, email, notes, \
                status, created_at, updated_at \
         FROM customers \
         WHERE status = $1 AND ($2::text IS NULL OR name ILIKE '%' || $2 || '%') \
         ORDER BY created_at DESC, id DESC LIMIT $3 OFFSET $4",
    )
    .bind(status.as_str())
    .bind(needle)
    .bind(limit)
    .bind(offset)
    .fetch_all(conn)
    .await?;

    assert!(
        i64::try_from(rows.len()).is_ok_and(|n| n <= limit),
        "LIMIT must bound the row count"
    );
    let mut customers = Vec::with_capacity(rows.len());
    for row in &rows {
        customers.push(Customer::try_from(row)?);
    }
    Ok(customers)
}

/// Applies a partial update to an active customer (`COALESCE`, so an absent field
/// is a no-op and no SQL is built from input, CLAUDE.md §10).
///
/// # Errors
///
/// [`CrmError::NotFound`] if no active customer has that id.
pub(crate) async fn patch_customer(
    conn: &mut PgConnection,
    customer: CustomerId,
    patch: &CustomerPatch<'_>,
) -> Result<Customer, CrmError> {
    let row = sqlx::query(
        "UPDATE customers SET \
             name = COALESCE($2, name), \
             tax_code = COALESCE($3, tax_code), \
             address = COALESCE($4, address), \
             phone = COALESCE($5, phone), \
             email = COALESCE($6, email), \
             notes = COALESCE($7, notes), \
             updated_at = now() \
         WHERE id = $1 AND status <> 'archived' \
         RETURNING id, tenant_id, code, name, tax_code, address, phone, email, notes, \
                   status, created_at, updated_at",
    )
    .bind(customer.as_uuid())
    .bind(patch.name.map(CustomerName::as_str))
    .bind(patch.tax_code.map(TaxCode::as_str))
    .bind(patch.address.map(Address::as_str))
    .bind(patch.phone.map(Phone::as_str))
    .bind(patch.email.map(EmailAddress::as_str))
    .bind(patch.notes.map(Notes::as_str))
    .fetch_optional(conn)
    .await?;
    let row = row.ok_or(CrmError::NotFound)?;
    Ok(Customer::try_from(&row)?)
}

/// Soft-archives a customer and, in the same transaction, all of its active
/// contacts — a contact must not outlive its parent as a mutable orphan (the
/// `/contacts/{id}` routes key on `ContactId` alone, and once archived those
/// rows 404). Idempotent at the API level: a second archive 404s.
///
/// # Errors
///
/// [`CrmError::NotFound`] if no active customer has that id.
pub(crate) async fn archive_customer(
    conn: &mut PgConnection,
    customer: CustomerId,
) -> Result<(), CrmError> {
    let result = sqlx::query(
        "UPDATE customers SET status = 'archived', updated_at = now() \
         WHERE id = $1 AND status <> 'archived'",
    )
    .bind(customer.as_uuid())
    .execute(&mut *conn)
    .await?;
    if result.rows_affected() == 0 {
        return Err(CrmError::NotFound);
    }
    sqlx::query(
        "UPDATE contacts SET status = 'archived', updated_at = now() \
         WHERE customer_id = $1 AND status <> 'archived'",
    )
    .bind(customer.as_uuid())
    .execute(conn)
    .await?;
    Ok(())
}

/// Verifies a customer is visible and active, taking a `FOR SHARE` lock on the
/// row so it cannot be archived until the caller's transaction commits.
///
/// This closes the create-contact race: a concurrent [`archive_customer`] (an
/// `UPDATE` on the same row) blocks until the contact insert commits, after
/// which its cascade archives the new contact too — so a contact can never be
/// committed active under a just-archived customer. Lighter than [`get_customer`]
/// (no row decode); RLS scopes it to the active tenant.
///
/// # Errors
///
/// [`CrmError::NotFound`] if no active customer has that id in this tenant.
pub(crate) async fn lock_active_customer(
    conn: &mut PgConnection,
    customer: CustomerId,
) -> Result<(), CrmError> {
    sqlx::query("SELECT 1 FROM customers WHERE id = $1 AND status <> 'archived' FOR SHARE")
        .bind(customer.as_uuid())
        .fetch_optional(conn)
        .await?
        .ok_or(CrmError::NotFound)?;
    Ok(())
}

/// Inserts a new active contact under a customer.
///
/// The caller verifies the customer is visible+active first, so the composite FK
/// is satisfied; a foreign-key violation (a missing/cross-tenant customer) is
/// nonetheless mapped to [`CrmError::NotFound`] rather than a generic `500`.
pub(crate) async fn insert_contact(
    conn: &mut PgConnection,
    tenant: TenantId,
    customer: CustomerId,
    new: &NewContact<'_>,
) -> Result<Contact, CrmError> {
    let result = sqlx::query(
        "INSERT INTO contacts \
         (tenant_id, customer_id, name, title, email, phone, is_primary) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         RETURNING id, tenant_id, customer_id, name, title, email, phone, is_primary, \
                   status, created_at, updated_at",
    )
    .bind(tenant.as_uuid())
    .bind(customer.as_uuid())
    .bind(new.name.as_str())
    .bind(new.title.map(ContactTitle::as_str))
    .bind(new.email.map(EmailAddress::as_str))
    .bind(new.phone.map(Phone::as_str))
    .bind(new.is_primary)
    .fetch_one(conn)
    .await;
    match result {
        Ok(row) => {
            let contact = Contact::try_from(&row)?;
            assert_eq!(
                contact.tenant_id, tenant,
                "row belongs to the active tenant"
            );
            Ok(contact)
        }
        Err(sqlx::Error::Database(dberr)) if dberr.is_foreign_key_violation() => {
            Err(CrmError::NotFound)
        }
        Err(error) => Err(error.into()),
    }
}

/// Lists a customer's active contacts (primary first, then oldest). Bounded by
/// [`limits::MAX_CONTACTS_PER_CUSTOMER`] (CLAUDE.md §5).
///
/// # Errors
///
/// [`CrmError::Db`] on query/decode failure.
pub(crate) async fn list_contacts(
    conn: &mut PgConnection,
    customer: CustomerId,
) -> Result<Vec<Contact>, CrmError> {
    let rows = sqlx::query(
        "SELECT id, tenant_id, customer_id, name, title, email, phone, is_primary, \
                status, created_at, updated_at \
         FROM contacts WHERE customer_id = $1 AND status <> 'archived' \
         ORDER BY is_primary DESC, created_at ASC, id ASC LIMIT $2",
    )
    .bind(customer.as_uuid())
    .bind(limits::MAX_CONTACTS_PER_CUSTOMER)
    .fetch_all(conn)
    .await?;

    assert!(
        i64::try_from(rows.len()).is_ok_and(|n| n <= limits::MAX_CONTACTS_PER_CUSTOMER),
        "LIMIT must bound the row count"
    );
    let mut contacts = Vec::with_capacity(rows.len());
    for row in &rows {
        contacts.push(Contact::try_from(row)?);
    }
    Ok(contacts)
}

/// Applies a partial update to an active contact (`COALESCE` per field).
///
/// # Errors
///
/// [`CrmError::NotFound`] if no active contact has that id.
pub(crate) async fn patch_contact(
    conn: &mut PgConnection,
    contact: ContactId,
    patch: &ContactPatch<'_>,
) -> Result<Contact, CrmError> {
    let row = sqlx::query(
        "UPDATE contacts SET \
             name = COALESCE($2, name), \
             title = COALESCE($3, title), \
             email = COALESCE($4, email), \
             phone = COALESCE($5, phone), \
             is_primary = COALESCE($6, is_primary), \
             updated_at = now() \
         WHERE id = $1 AND status <> 'archived' \
         RETURNING id, tenant_id, customer_id, name, title, email, phone, is_primary, \
                   status, created_at, updated_at",
    )
    .bind(contact.as_uuid())
    .bind(patch.name.map(ContactName::as_str))
    .bind(patch.title.map(ContactTitle::as_str))
    .bind(patch.email.map(EmailAddress::as_str))
    .bind(patch.phone.map(Phone::as_str))
    .bind(patch.is_primary)
    .fetch_optional(conn)
    .await?;
    let row = row.ok_or(CrmError::NotFound)?;
    Ok(Contact::try_from(&row)?)
}

/// Soft-archives a contact (status → `archived`).
///
/// # Errors
///
/// [`CrmError::NotFound`] if no active contact has that id.
pub(crate) async fn archive_contact(
    conn: &mut PgConnection,
    contact: ContactId,
) -> Result<(), CrmError> {
    let result = sqlx::query(
        "UPDATE contacts SET status = 'archived', updated_at = now() \
         WHERE id = $1 AND status <> 'archived'",
    )
    .bind(contact.as_uuid())
    .execute(conn)
    .await?;
    if result.rows_affected() == 0 {
        return Err(CrmError::NotFound);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Repo CRUD, the code generator, and Row-Level Security, against real
    //! Postgres. Like `assets::repo::tests`, we connect as the least-privilege
    //! `erp_app` role so the `*_tenant_isolation` policies are genuinely exercised
    //! (the admin pool `#[sqlx::test]` provides bypasses RLS).

    use super::{
        ContactPatch, CustomerPatch, NewContact, NewCustomer, archive_contact, archive_customer,
        get_customer, insert_contact, insert_customer, list_contacts, list_customers,
        patch_contact, patch_customer,
    };
    use crate::crm::error::CrmError;
    use crate::crm::model::{ContactName, CustomerName, RecordStatus};
    use crate::db::begin_tenant_tx;
    use crate::db::test_support::{app_pool, new_tenant, seed_tenant};
    use crate::domain::{CustomerId, Phone, TenantId};
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use sqlx::{Connection as _, PgConnection, PgPool};
    use uuid::Uuid;

    fn name(s: &str) -> CustomerName {
        CustomerName::try_from(s.to_owned()).expect("valid name")
    }

    fn contact_name(s: &str) -> ContactName {
        ContactName::try_from(s.to_owned()).expect("valid contact name")
    }

    fn new_customer(n: &CustomerName) -> NewCustomer<'_> {
        NewCustomer {
            name: n,
            tax_code: None,
            address: None,
            phone: None,
            email: None,
            notes: None,
        }
    }

    /// Inserts a customer in the tenant context and commits, returning it.
    async fn seed_customer(pool: &PgPool, tenant: TenantId, n: &str) -> CustomerId {
        let name = name(n);
        let mut tx = begin_tenant_tx(pool, tenant).await.expect("begin");
        let customer = insert_customer(&mut tx, tenant, &new_customer(&name))
            .await
            .expect("insert customer");
        tx.commit().await.expect("commit");
        customer.id
    }

    #[sqlx::test]
    async fn insert_then_get_round_trips(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = app_pool(opts, conn).await;
        let tenant = new_tenant();
        seed_tenant(&pool, tenant, "tenant-a").await;
        let id = seed_customer(&pool, tenant, "Acme Print").await;

        let mut tx = begin_tenant_tx(&pool, tenant).await.expect("begin");
        let got = get_customer(&mut tx, tenant, id).await.expect("get");
        assert_eq!(got.id, id);
        assert_eq!(got.code.as_str(), "CS001", "first customer gets CS001");
        assert_eq!(got.name.as_str(), "Acme Print");
        assert_eq!(got.status, RecordStatus::Active);
    }

    #[sqlx::test]
    async fn codes_are_sequential_within_a_tenant(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = app_pool(opts, conn).await;
        let tenant = new_tenant();
        seed_tenant(&pool, tenant, "tenant-a").await;

        let codes = {
            let names = [name("A"), name("B"), name("C")];
            let mut tx = begin_tenant_tx(&pool, tenant).await.expect("begin");
            let mut out = Vec::new();
            for n in &names {
                out.push(
                    insert_customer(&mut tx, tenant, &new_customer(n))
                        .await
                        .expect("insert")
                        .code,
                );
            }
            tx.commit().await.expect("commit");
            out
        };
        let as_str: Vec<&str> = codes
            .iter()
            .map(crate::crm::model::CustomerCode::as_str)
            .collect();
        assert_eq!(as_str, ["CS001", "CS002", "CS003"]);
    }

    #[sqlx::test]
    async fn codes_restart_per_tenant(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = app_pool(opts, conn).await;
        let (a, b) = (new_tenant(), new_tenant());
        seed_tenant(&pool, a, "tenant-a").await;
        seed_tenant(&pool, b, "tenant-b").await;

        let id_a = seed_customer(&pool, a, "A-first").await;
        let id_b = seed_customer(&pool, b, "B-first").await;

        let mut tx_a = begin_tenant_tx(&pool, a).await.expect("begin");
        assert_eq!(
            get_customer(&mut tx_a, a, id_a)
                .await
                .expect("get")
                .code
                .as_str(),
            "CS001"
        );
        let mut tx_b = begin_tenant_tx(&pool, b).await.expect("begin");
        assert_eq!(
            get_customer(&mut tx_b, b, id_b)
                .await
                .expect("get")
                .code
                .as_str(),
            "CS001",
            "tenant B's sequence is independent"
        );
    }

    #[sqlx::test]
    async fn concurrent_creates_get_distinct_sequential_codes(
        opts: PgPoolOptions,
        conn: PgConnectOptions,
    ) {
        let pool = app_pool(opts, conn).await;
        let tenant = new_tenant();
        seed_tenant(&pool, tenant, "tenant-a").await;

        // Two creates race in separate transactions. The counter row lock
        // serializes them, so they get distinct, gap-free codes — never the same.
        let create = |label: &'static str| {
            let pool = pool.clone();
            async move {
                let name = name(label);
                let mut tx = begin_tenant_tx(&pool, tenant).await.expect("begin");
                let code = insert_customer(&mut tx, tenant, &new_customer(&name))
                    .await
                    .expect("insert")
                    .code;
                tx.commit().await.expect("commit");
                code.as_str().to_owned()
            }
        };
        let (first, second) = tokio::join!(create("one"), create("two"));
        assert_ne!(first, second, "concurrent creates never share a code");
        // The two allocated codes are exactly {CS001, CS002}, in either order.
        let seen = format!("{first},{second}");
        assert!(seen.contains("CS001"), "one create is CS001, got {seen}");
        assert!(seen.contains("CS002"), "the other is CS002, got {seen}");
    }

    #[sqlx::test]
    async fn archive_hides_customer_from_get_and_list(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = app_pool(opts, conn).await;
        let tenant = new_tenant();
        seed_tenant(&pool, tenant, "tenant-a").await;
        let id = seed_customer(&pool, tenant, "Acme").await;

        let mut tx = begin_tenant_tx(&pool, tenant).await.expect("begin");
        archive_customer(&mut tx, id).await.expect("archive");
        assert!(
            matches!(
                get_customer(&mut tx, tenant, id).await,
                Err(CrmError::NotFound)
            ),
            "archived customer is invisible to get"
        );
        let active = list_customers(&mut tx, RecordStatus::Active, None, 50, 0)
            .await
            .expect("list active");
        assert!(active.is_empty(), "archived excluded from the active list");
        let archived = list_customers(&mut tx, RecordStatus::Archived, None, 50, 0)
            .await
            .expect("list archived");
        assert_eq!(archived.len(), 1, "but visible under the archived filter");
    }

    #[sqlx::test]
    async fn list_paginates_and_filters_by_name(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = app_pool(opts, conn).await;
        let tenant = new_tenant();
        seed_tenant(&pool, tenant, "tenant-a").await;
        seed_customer(&pool, tenant, "Alpha Co").await;
        seed_customer(&pool, tenant, "Beta Co").await;
        seed_customer(&pool, tenant, "Gamma Co").await;

        let mut tx = begin_tenant_tx(&pool, tenant).await.expect("begin");
        let page = list_customers(&mut tx, RecordStatus::Active, None, 2, 0)
            .await
            .expect("first page");
        assert_eq!(page.len(), 2, "limit caps the page");
        let rest = list_customers(&mut tx, RecordStatus::Active, None, 2, 2)
            .await
            .expect("second page");
        assert_eq!(rest.len(), 1, "offset reaches the remainder");

        let hit = list_customers(&mut tx, RecordStatus::Active, Some("alph"), 50, 0)
            .await
            .expect("search");
        assert_eq!(
            hit.len(),
            1,
            "case-insensitive name filter narrows the list"
        );
        assert_eq!(hit[0].name.as_str(), "Alpha Co");
    }

    #[sqlx::test]
    async fn patch_updates_named_fields_only(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = app_pool(opts, conn).await;
        let tenant = new_tenant();
        seed_tenant(&pool, tenant, "tenant-a").await;
        let id = seed_customer(&pool, tenant, "Old Name").await;

        let new_name = name("New Name");
        let new_phone = Phone::try_from("0900-111-222".to_owned()).expect("valid phone");
        let patch = CustomerPatch {
            name: Some(&new_name),
            tax_code: None,
            address: None,
            phone: Some(&new_phone),
            email: None,
            notes: None,
        };
        let mut tx = begin_tenant_tx(&pool, tenant).await.expect("begin");
        let updated = patch_customer(&mut tx, id, &patch).await.expect("patch");
        assert_eq!(updated.name.as_str(), "New Name");
        assert_eq!(
            updated.phone.as_ref().map(Phone::as_str),
            Some("0900-111-222")
        );
        assert_eq!(updated.code.as_str(), "CS001", "code is immutable");
    }

    #[sqlx::test]
    async fn patch_missing_customer_is_not_found(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = app_pool(opts, conn).await;
        let tenant = new_tenant();
        seed_tenant(&pool, tenant, "tenant-a").await;

        let new_name = name("X");
        let patch = CustomerPatch {
            name: Some(&new_name),
            tax_code: None,
            address: None,
            phone: None,
            email: None,
            notes: None,
        };
        let absent = CustomerId::try_from(Uuid::new_v4()).expect("non-nil");
        let mut tx = begin_tenant_tx(&pool, tenant).await.expect("begin");
        assert!(matches!(
            patch_customer(&mut tx, absent, &patch).await,
            Err(CrmError::NotFound)
        ));
    }

    fn new_contact(n: &ContactName, primary: bool) -> NewContact<'_> {
        NewContact {
            name: n,
            title: None,
            email: None,
            phone: None,
            is_primary: primary,
        }
    }

    #[sqlx::test]
    async fn contact_insert_list_patch_archive(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = app_pool(opts, conn).await;
        let tenant = new_tenant();
        seed_tenant(&pool, tenant, "tenant-a").await;
        let customer = seed_customer(&pool, tenant, "Acme").await;

        let primary = contact_name("Alice");
        let mut tx = begin_tenant_tx(&pool, tenant).await.expect("begin");
        let contact = insert_contact(&mut tx, tenant, customer, &new_contact(&primary, true))
            .await
            .expect("insert contact");
        assert!(contact.is_primary);

        let listed = list_contacts(&mut tx, customer).await.expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name.as_str(), "Alice");

        let renamed = contact_name("Alice Updated");
        let patch = ContactPatch {
            name: Some(&renamed),
            title: None,
            email: None,
            phone: None,
            is_primary: Some(false),
        };
        let updated = patch_contact(&mut tx, contact.id, &patch)
            .await
            .expect("patch");
        assert_eq!(updated.name.as_str(), "Alice Updated");
        assert!(!updated.is_primary);

        archive_contact(&mut tx, contact.id).await.expect("archive");
        assert!(
            list_contacts(&mut tx, customer)
                .await
                .expect("relist")
                .is_empty(),
            "archived contact is excluded"
        );
    }

    #[sqlx::test]
    async fn contact_under_missing_customer_is_not_found(
        opts: PgPoolOptions,
        conn: PgConnectOptions,
    ) {
        let pool = app_pool(opts, conn).await;
        let tenant = new_tenant();
        seed_tenant(&pool, tenant, "tenant-a").await;

        let absent = CustomerId::try_from(Uuid::new_v4()).expect("non-nil");
        let nm = contact_name("Bob");
        let mut tx = begin_tenant_tx(&pool, tenant).await.expect("begin");
        assert!(
            matches!(
                insert_contact(&mut tx, tenant, absent, &new_contact(&nm, false)).await,
                Err(CrmError::NotFound)
            ),
            "a contact under no customer is rejected via the FK"
        );
    }

    #[sqlx::test]
    async fn contact_cannot_reference_another_tenants_customer(
        opts: PgPoolOptions,
        conn: PgConnectOptions,
    ) {
        let pool = app_pool(opts, conn).await;
        let (a, b) = (new_tenant(), new_tenant());
        seed_tenant(&pool, a, "tenant-a").await;
        seed_tenant(&pool, b, "tenant-b").await;
        let b_customer = seed_customer(&pool, b, "B Co").await;

        // In tenant A's context, try to attach a contact to tenant B's customer.
        // The composite FK on (tenant_id, customer_id) → customers(tenant_id, id)
        // has no matching (A, b_customer) row, so the insert is refused.
        let nm = contact_name("Mallory");
        let mut tx = begin_tenant_tx(&pool, a).await.expect("begin");
        assert!(matches!(
            insert_contact(&mut tx, a, b_customer, &new_contact(&nm, false)).await,
            Err(CrmError::NotFound)
        ));
    }

    #[sqlx::test]
    async fn archiving_customer_cascades_to_its_contacts(
        opts: PgPoolOptions,
        conn: PgConnectOptions,
    ) {
        let pool = app_pool(opts, conn).await;
        let tenant = new_tenant();
        seed_tenant(&pool, tenant, "tenant-a").await;
        let customer = seed_customer(&pool, tenant, "Acme").await;

        let nm = contact_name("Alice");
        let mut tx = begin_tenant_tx(&pool, tenant).await.expect("begin");
        let contact = insert_contact(&mut tx, tenant, customer, &new_contact(&nm, true))
            .await
            .expect("insert contact");

        // Archiving the customer archives its contacts in the same transaction.
        archive_customer(&mut tx, customer).await.expect("archive");
        assert!(
            list_contacts(&mut tx, customer)
                .await
                .expect("list")
                .is_empty(),
            "child contacts are archived with the customer"
        );
        // The orphaned contact can no longer be mutated by id (both routes 404).
        assert!(matches!(
            archive_contact(&mut tx, contact.id).await,
            Err(CrmError::NotFound)
        ));
        let renamed = contact_name("X");
        let patch = ContactPatch {
            name: Some(&renamed),
            title: None,
            email: None,
            phone: None,
            is_primary: None,
        };
        assert!(matches!(
            patch_contact(&mut tx, contact.id, &patch).await,
            Err(CrmError::NotFound)
        ));
    }

    #[sqlx::test]
    async fn rls_scopes_customers_to_their_tenant(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = app_pool(opts, conn).await;
        let (a, b) = (new_tenant(), new_tenant());
        seed_tenant(&pool, a, "tenant-a").await;
        seed_tenant(&pool, b, "tenant-b").await;
        seed_customer(&pool, a, "A Co").await;
        seed_customer(&pool, b, "B Co").await;

        let mut tx = begin_tenant_tx(&pool, a).await.expect("begin");
        let listed = list_customers(&mut tx, RecordStatus::Active, None, 50, 0)
            .await
            .expect("list");
        assert_eq!(listed.len(), 1, "tenant A sees only its own customer");
        assert_eq!(listed[0].tenant_id, a);
    }

    #[sqlx::test]
    async fn no_tenant_context_denies_all_customers(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = app_pool(opts, conn).await;
        let a = new_tenant();
        seed_tenant(&pool, a, "tenant-a").await;
        seed_customer(&pool, a, "A Co").await;

        let mut tx = pool.begin().await.expect("begin plain tx");
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM customers")
            .fetch_one(&mut *tx)
            .await
            .expect("count without context");
        assert_eq!(count, 0, "no tenant context exposes zero customers");
    }

    #[sqlx::test]
    async fn cross_tenant_customer_insert_is_rejected(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = app_pool(opts, conn).await;
        let (a, b) = (new_tenant(), new_tenant());
        seed_tenant(&pool, a, "tenant-a").await;
        seed_tenant(&pool, b, "tenant-b").await;

        // In A's context, write a row stamped for tenant B.
        let mut tx = begin_tenant_tx(&pool, a).await.expect("begin");
        let result =
            sqlx::query("INSERT INTO customers (tenant_id, code, name) VALUES ($1, $2, $3)")
                .bind(b.as_uuid())
                .bind("CS001")
                .bind("Intruder")
                .execute(&mut *tx)
                .await;
        let err = result.expect_err("WITH CHECK must reject the cross-tenant insert");
        assert!(
            err.to_string().contains("row-level security"),
            "rejection must come from the RLS policy, got: {err}"
        );
    }

    #[sqlx::test]
    async fn crm_migration_is_reversible(_opts: PgPoolOptions, conn: PgConnectOptions) {
        // Run as the admin role (DDL). Reverting *to* the auth_tokens version
        // undoes only the crm migration (the one applied after it): the tables
        // appear, vanish on undo, and return on re-apply (CLAUDE.md §13).
        let mut admin = PgConnection::connect_with(&conn)
            .await
            .expect("admin connection");
        let migrator = sqlx::migrate!("./migrations");

        let forced: bool = sqlx::query_scalar(FORCE_RLS_CUSTOMERS)
            .fetch_one(&mut admin)
            .await
            .expect("read forcerowsecurity");
        assert!(forced, "migration leaves FORCE RLS enabled on customers");

        migrator
            .undo(&mut admin, AUTH_TOKENS_MIGRATION_VERSION)
            .await
            .expect("revert the crm migration");
        let after_undo: Option<String> =
            sqlx::query_scalar("SELECT to_regclass('customers')::text")
                .fetch_one(&mut admin)
                .await
                .expect("read to_regclass after undo");
        assert!(
            after_undo.is_none(),
            "down migration drops the customers table"
        );

        migrator.run(&mut admin).await.expect("re-apply");
        let forced_again: bool = sqlx::query_scalar(FORCE_RLS_CUSTOMERS)
            .fetch_one(&mut admin)
            .await
            .expect("read forcerowsecurity after re-apply");
        assert!(forced_again, "re-applied migration re-enables FORCE RLS");
    }

    /// Reverting *to* this version (the auth_tokens migration) undoes the crm one.
    const AUTH_TOKENS_MIGRATION_VERSION: i64 = 20_260_624_000_004;

    /// Reads whether `customers` has `FORCE ROW LEVEL SECURITY` set.
    const FORCE_RLS_CUSTOMERS: &str =
        "SELECT relforcerowsecurity FROM pg_class WHERE relname = 'customers'";
}
