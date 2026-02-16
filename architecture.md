# GovConMoney System Architecture

Date: 2026-02-16

## 1. Overview

GovConMoney is a multi-tenant government-contractor accounting platform built on .NET and Blazor Server.  
It combines timekeeping, accounting, compliance, billing, and audit evidence generation in a single system.

This system is designed to support an accounting system adequacy demonstration by generating reproducible evidence artifacts aligned to DFARS 252.242-7006 criteria.

Primary goals:
- Enforce role-based financial controls.
- Keep auditable, append-only event history.
- Support DFARS/DCAA-oriented reporting and audit binder outputs.

Management review architecture update:
- Management-review controls now include a periodic internal-audit and attestation subsystem.
- Policy configuration governs cadence, due window, and required attestation roles.
- Completion is workflow-gated until required attestations are recorded.

## 2. Runtime Topology

Main runtime components:
- `GovConMoney.Web` (Blazor Server UI + minimal API endpoints + auth + hosted jobs)
- `GovConMoney.Application` (business services, workflow logic, reporting/export)
- `GovConMoney.Domain` (entities, enums, domain records)
- `GovConMoney.Infrastructure` (EF Core DbContext, tenant scoping, repository, audit context)
- `GovConMoney.Tests` (scenario-style integration tests + binder artifact generation)

Execution model:
- Request/response workflows run in web/API endpoints.
- Domain logic executes in application services.
- Persistence is handled via EF Core through repository abstractions.
- Daily compliance cadence monitoring runs as a hosted background service.

## 3. Layered Architecture

    Blazor UI/API -> Application Services -> EF Core DbContext -> SQL 
                      |
                      v
              AuditEvent append-only log
                      |
                      v
             Evidence Binder Export (Tests)

### 3.1 Presentation and API Layer
- Entry point: `GovConMoney.Web/Program.cs`
- Blazor pages under `GovConMoney.Web/Components/Pages/*`
- API/form endpoints for operational actions (timesheets, approvals, close, billing, reporting)

### 3.2 Application Service Layer
Key services:
- `TimesheetService` (draft/submit/approve/correct + expense flow)
- `AccountingService` (posting operations)
- `IndirectRateService` (compute/apply/rerate + manager review for final rates)
- `JournalEntryWorkflowService` (adjusting JE maker-checker workflow)
- `BillingService` (billing run generation, approval, posting, reconciliation)
- `CloseService` (pre-close validation, period close, tie-out, trial balance)
- `MonthlyCloseComplianceService` (close cadence reporting)
- `ReportingService` (operational/compliance reports + export support)

### 3.3 Domain Layer
Core entities include:
- Organizational/compliance: `Tenant`, `AppUser`, `ManagementReviewPolicy`, `AuditEvent`
- Timekeeping: `Timesheet`, `TimesheetLine`, `TimesheetExpense`, `CorrectionRequest`
- Contract hierarchy: `Contract`, `TaskOrder`, `Clin`, `WbsNode`, `ChargeCode`
- Accounting: `ChartOfAccount`, `JournalEntry`, `JournalLine`, `AccountingPeriod`
- Indirect engine: `IndirectPool`, `AllocationBase`, `RateCalculation`, `AppliedBurdenEntry`
- Billing: `BillingRun`, `Invoice`, `InvoiceLine`, `BilledCostLink`, `BillingCeiling`

### 3.4 Infrastructure Layer
- `GovConMoney.Infrastructure/Persistence/GovConMoneyDbContext.cs`
- Tenant query filtering via `TenantId`.
- Append-only and immutability enforcement for audit and ledger entities.
- In-memory persistence and test harness support in `Infrastructure/Persistence/*`.

## 4. Data and Tenancy Architecture

Multi-tenant model:
- Business entities implement tenant scoping and include `TenantId`.
- Global query filters enforce tenant isolation in EF Core.

Control-oriented data behavior:
- `AuditEvent` is append-only (no update/delete).
- `JournalLine` is immutable.
- Posted/reversed `JournalEntry` records are immutable except controlled reversal status transition.

## 5. Security Architecture

Authentication and authorization:
- ASP.NET Core Identity + cookie authentication in `GovConMoney.Web/Program.cs`.
- Role policies (`Admin`, `Compliance`, `TimeReporter`, `Supervisor`, `Accountant`, `Manager`).
- Manager/accountant split used in financial approvals.

Hardening controls:
- Secure cookie settings.
- Rate limiting for auth endpoints.
- Passkey/WebAuthn services in `GovConMoney.Web/Security/*`.

## 6. Core Business Workflows

### 6.1 Timekeeping and Posting
1. Time reporter creates/submits timesheet.
2. Supervisor approves.
3. Accountant posts approved time to ledger.
4. Compliance and audit events are captured.

### 6.2 Indirect Rate Lifecycle
1. Accountant computes rates from posted books.
2. Final rates move to manager review lifecycle.
3. Manager approves/rejects final rates.
4. Burden is applied (and optionally rerated) and can be posted to GL.

### 6.3 Billing Lifecycle
1. Accountant generates billing run from posted allowable costs.
2. Threshold policy may require manager approval.
3. Approved billing run is posted to GL and invoices.
4. Billed-to-booked reconciliation is produced.

### 6.4 Period Close and Monthly Cadence
1. Pre-close validation checks tie-outs and accounting prerequisites.
2. Manager closes accounting period.
3. Monthly close compliance service reports overdue periods.
4. Hosted daily job emits compliance/escalation notifications for overdue periods.

### 6.5 Periodic Internal Audit and Attestation
1. Internal audit cycles are synchronized from accounting periods.
2. Checklist steps (tie-out, unallowables, billing, monthly close) are recorded on each cycle.
3. Cycle is submitted for attestation after checklist completion.
4. Manager and compliance attestations are captured as explicit records (policy-driven requirements).
5. Cycle completion is manager-gated until required attestations are present.
6. Compliance report tracks overdue cycles and attestation completeness.

This supports DFARS 252.242-7006(c)(11) routine posting and interim cost determination.

## 7. Reporting and Audit Evidence Architecture

Report and export mechanisms:
- API report endpoints in `GovConMoney.Web/Program.cs` (CSV/JSON).
- Report composition in `GovConMoney.Application/Services/ReportingService.cs`.
- Export formatter in `ExportService` (CSV/JSON).

Audit binder generation:
- Implemented in `GovConMoney.Tests/Program.cs` test `Generate auditor binder evidence package`.
- Output root: `GovConMoney.Tests/Runner/AuditBinderOutput/<timestamp_guid>/`.

Current binder artifacts include:
- `timesheets_packet`
- `timesheet_compliance`
- `labor_distribution`
- `project_summary`
- `clin_summary`
- `indirect_rate_support`
- `applied_burden_summary`
- `general_journal`
- `trial_balance`
- `subledger_gl_tieout`
- `monthly_close_compliance`
- `internal_audit_compliance`
- `internal_audit_cycles`
- `internal_audit_attestations`
- `unallowable_costs`
- `invoices`
- `invoice_lines`
- `billed_cost_links`
- `billed_to_booked_reconciliation`
- `adjusting_je_packet`
- `manager_review_events`
- `audit_trail`

## 8. Background Processing

Hosted service:
- `GovConMoney.Web/Services/MonthlyCloseComplianceHostedService.cs`
- Registered in `GovConMoney.Web/Program.cs` with `AddHostedService`.
- Runs periodic checks for overdue open accounting periods and sends notifications/escalations.

## 9. Test Architecture

Test runner:
- `GovConMoney.Tests/Program.cs`
- Scenario tests validate control behavior (security, workflows, accounting, reconciliation, compliance reporting).

Coverage style:
- End-to-end service-level checks in an in-memory environment.
- Binder-generation scenario verifies creation of required audit artifacts.

## 10. Known Architectural Gaps

Current intentional/known gaps:
- No full FAR limitation-clause notice/escalation workflow model.
- No explicit preproduction vs production cost-phase model yet.
- No CAS-specific rules engine/mapping repository.

These gaps are reflected in compliance statuses in `compliance.md` and `Clause-to-Control-Matrix.md`.
