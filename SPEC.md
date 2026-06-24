# SPEC — data model & pipeline

Technical reference for the Printing ERP domain. Read this before non-trivial
changes (CLAUDE.md depends on it). This describes *what the system models*, not
market or business analysis.

## Pipeline (order-to-delivery)

The product standardizes one core flow and makes the production steps within it
configurable per tenant and product type:

```
RFQ ─▶ Estimate ─▶ Quote ─▶ Order ─▶ Job ─▶ JobOperation* ─▶ Shipment ─▶ Invoice ─▶ Payment
                                       │
                                       └─▶ tracked on the shop floor in real time
```

1. **RFQ** — customer request with print specs (size, colors, stock, quantity, finishing).
2. **Estimate** — the estimating engine prices paper + ink + press time + finishing + waste/scrap.
3. **Quote** — a presented, versioned price; approval converts it to an order.
4. **Order** — confirmed work with delivery dates and attached artwork.
5. **Job** — production work order generated from the order.
6. **JobOperation** — ordered routing steps (prepress → press → finishing → QC).
7. **Shop-floor tracking** — operators start/stop operations; time and material consumption are recorded live.
8. **Shipment** — packing list / delivery note.
9. **Invoice / Payment** — billing and accounts-receivable.

The production segment (steps 5–7) varies by print method (offset vs digital vs
flexo/gravure) and finishing; it is modeled as a configurable **routing + dynamic
BOM**, not hard-coded.

## Core entities

| Entity | Notes |
| --- | --- |
| `Tenant` | One printing business. Root of all tenant-scoped data. |
| `User` | Belongs to a tenant; carries a `Role` (admin/sales/coordinator/scheduler/operator). |
| `Customer` / `Contact` | A tenant's clients and their contacts. |
| `Material` / `InventoryLot` | Paper, ink, laminate, … and on-hand stock by lot. |
| `Machine` (cost center) | Press/cutter/etc., with hourly rates and speed tables. |
| `ProductTemplate` / `BOM` | Per-product-type bill-of-materials and consumption norms. |
| `Estimate` / `EstimateLine` | Priced breakdown produced by the estimating engine. |
| `Quote` → `Order` → `Job` | Lifecycle of confirmed work. |
| `JobOperation` | A routing step; parent of `TimeEntry` and `MaterialConsumption`. |
| `QCCheck` / `ProofApproval` / `ArtFile` | Quality, proofing and artwork attached to a job. |
| `Shipment` / `Invoice` / `Payment` | Fulfillment and billing. |
| `AuditLog` / `Notification` | Cross-cutting. |

Identifiers are newtypes (see `erp-domain`); a bare `Uuid`/`String` id is a bug.

## Tenancy

Every tenant-scoped row carries a `tenant_id`. Isolation is enforced in two
layers: the application always filters by tenant, and PostgreSQL **Row-Level
Security** is the backstop against a missing `WHERE tenant_id` (CLAUDE.md §10).

Mechanism: each request opens a transaction that sets the `app.current_tenant`
GUC (via `db::begin_tenant_tx`); a `FORCE ROW LEVEL SECURITY` policy on every
tenant-scoped table compares `tenant_id` to that GUC — an unset GUC sees no rows
(default-deny). For the policy to bind, the **serving role must be non-superuser
and `NOBYPASSRLS`** (superusers bypass RLS entirely): the app serves as the
least-privilege `erp_app` role and runs migrations as the admin `erp` role.

## Retry and idempotency

State-changing operations are designed to be safely retryable. Long-running
work (PDF export, e-invoice submission, notifications) is dispatched to the
Redis-backed job queue with an **idempotency key** so a retried or duplicated
message does not double-apply. A worker that crashes loses its lease; another
worker resumes the unit of work (this is why `panic = "abort"` is acceptable —
see CLAUDE.md §6).

## Status

Scaffold stage. Implemented so far: the multi-tenant foundation
(`tenants`, `users`, and **Row-Level Security** enforced via the `erp_app`
serving role) and the platform skeleton (config, telemetry, DB pool, health
probes). Subsequent migrations introduce the entities above following the
pipeline order, each repeating the RLS pattern on its tenant-scoped tables.
