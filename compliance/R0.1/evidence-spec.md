# Compliance Evidence Specification

Release: `R0.1`  
Date: 2026-02-25  
Scope: Audit-binder evidence artifacts produced by `Generate auditor binder evidence package` in `GovConMoney.Tests/Program.cs`.
Requirement source: `compliance/dfars.txt` (18 DFARS 252.242-7006 criteria).

## 1) Required CSV Formats

All evidence CSV artifacts must follow these rules:

- File location: `GovConMoney.Tests/Runner/AuditBinderOutput/<timestamp_guid>/`
- File extension: `.csv`
- Delimiter: comma (`,`)
- Header row: required, first row only
- Header names: exact C# property names from exported row/entity type (case-sensitive)
- Quote/escape rules: RFC4180-style (`"` wraps fields containing comma/quote/newline; internal quotes doubled)
- Decimal format: invariant `.` decimal separator (from default `.ToString()` in current runtime culture; compliance environment should run invariant culture for determinism)
- Date format:
  - `DateOnly`: `yyyy-MM-dd`
  - `DateTime`: ISO-like runtime format (example in evidence may appear locale-formatted if culture changes)
- Empty datasets: valid empty file (no header/content) under current exporter behavior

Generator reference:
- `GovConMoney.Application/Services/ReportingService.cs` (`ExportService.ToCsv`)
- `GovConMoney.Tests/Program.cs` (`WriteArtifact`)

## 2) Required Report Columns

The following CSV artifacts are required in each binder package. Columns are required by name.

### `timesheets_packet.csv`
Required columns:
- `TimesheetId`
- `UserId`
- `PeriodStart`
- `PeriodEnd`
- `Status`
- `VersionNumber`
- `SubmittedAtUtc`
- `ApprovedAtUtc`
- `PostedAtUtc`
- `ApprovalCount`
- `CorrectionCount`

### `labor_distribution.csv`
Required columns:
- `Employee`
- `ChargeCode`
- `Minutes`
- `LaborDollars`

### `project_summary.csv`
Required columns:
- `ContractNumber`
- `DirectCost`
- `AllocatedIndirect`
- `Unallowable`

### `timesheet_compliance.csv`
Required columns:
- `Employee`
- `MissingDays`
- `LateSubmissions`
- `CorrectionCount`
- `DailyEntryViolations`

### `clin_summary.csv`
Required columns:
- `ContractId`
- `ContractNumber`
- `TaskOrderId`
- `TaskOrderNumber`
- `ClinId`
- `ClinNumber`
- `WbsNodeId`
- `WbsCode`
- `ChargeCodeId`
- `ChargeCode`
- `CostType`
- `LaborHours`
- `LaborDollars`
- `ExpenseDollars`
- `AppliedBurdenDollars`
- `TotalDollars`

### `indirect_rate_support.csv`
Required columns:
- `IndirectPoolId`
- `PoolName`
- `RateCalculationId`
- `PeriodStart`
- `PeriodEnd`
- `PoolCost`
- `AllocationBaseTotal`
- `Rate`
- `Version`
- `IsFinal`
- `CalculatedAtUtc`
- `ReviewStatus`
- `SubmittedForReviewByUserId`
- `SubmittedForReviewAtUtc`
- `ReviewedByUserId`
- `ReviewedAtUtc`
- `ReviewNote`

### `applied_burden_summary.csv`
Required columns:
- `RateCalculationId`
- `IndirectPoolId`
- `PoolName`
- `PeriodStart`
- `PeriodEnd`
- `EntryCount`
- `BaseAmountTotal`
- `BurdenAmountTotal`
- `Rate`
- `IsAdjustment`
- `PostedToGeneralLedger`

### `trial_balance.csv`
Required columns:
- `AccountNumber`
- `AccountName`
- `Debit`
- `Credit`
- `Net`

### `general_journal.csv`
Required columns:
- `JournalEntryId`
- `EntryDate`
- `Description`
- `AccountNumber`
- `AccountName`
- `Debit`
- `Credit`

### `subledger_gl_tieout.csv`
Required columns:
- `Area`
- `SubledgerAmount`
- `GlAmount`
- `Variance`
- `Status`

### `monthly_close_compliance.csv`
Required columns:
- `AccountingPeriodId`
- `StartDate`
- `EndDate`
- `Status`
- `CloseDeadline`
- `DaysPastEnd`
- `DaysPastCloseDeadline`
- `JournalEntryCount`
- `IsOverdue`

### `internal_audit_compliance.csv`
Required columns:
- `InternalAuditCycleId`
- `PeriodStart`
- `PeriodEnd`
- `DueDate`
- `Status`
- `DaysPastDue`
- `IsOverdue`
- `RequiredAttestations`
- `ReceivedAttestations`
- `AllChecklistStepsComplete`

### `internal_audit_cycles.csv`
Required columns:
- `InternalAuditCycleId`
- `AccountingPeriodId`
- `PeriodStart`
- `PeriodEnd`
- `DueDate`
- `Status`
- `TieOutReviewCompleted`
- `UnallowableReviewCompleted`
- `BillingReviewCompleted`
- `MonthlyCloseReviewCompleted`
- `AttestationCount`
- `SubmittedAtUtc`
- `CompletedAtUtc`
- `Summary`
- `Notes`

### `internal_audit_attestations.csv`
Required columns:
- `InternalAuditCycleId`
- `AttestationId`
- `AttestationType`
- `AttestedByUserId`
- `AttestedByRoles`
- `AttestedAtUtc`
- `Statement`
- `Notes`

### `unallowable_costs.csv`
Required columns:
- `SourceEntityType`
- `SourceEntityId`
- `TimesheetId`
- `EntryDate`
- `Employee`
- `ChargeCode`
- `ContractNumber`
- `TaskOrderNumber`
- `ClinNumber`
- `WbsCode`
- `CostType`
- `AccountingCategory`
- `Amount`
- `ExcludedFromBilling`
- `ExclusionBasis`

### `invoices.csv`
Required columns:
- `Id`
- `TenantId`
- `BillingRunId`
- `ContractId`
- `InvoiceNumber`
- `PeriodStart`
- `PeriodEnd`
- `Status`
- `TotalAmount`
- `CreatedAtUtc`
- `PostedJournalEntryId`

### `invoice_lines.csv`
Required columns:
- `Id`
- `TenantId`
- `InvoiceId`
- `ContractId`
- `TaskOrderId`
- `ClinId`
- `WbsNodeId`
- `ChargeCodeId`
- `CostType`
- `CostElement`
- `Quantity`
- `Rate`
- `Amount`
- `IsAllowable`
- `Description`

### `billed_cost_links.csv`
Required columns:
- `Id`
- `TenantId`
- `InvoiceLineId`
- `SourceEntityType`
- `SourceEntityId`
- `Amount`

### `billed_to_booked_reconciliation.csv`
Required columns:
- `ContractId`
- `ContractNumber`
- `PeriodStart`
- `PeriodEnd`
- `BookedAllowable`
- `BilledAmount`
- `Variance`
- `Status`
- `BillingLimit`
- `BilledToDate`

### `adjusting_je_packet.csv`
Required columns:
- `JournalEntryId`
- `EntryDate`
- `Status`
- `IsReversal`
- `ReversalOfJournalEntryId`
- `RequestedByUserId`
- `ApprovedByUserId`
- `PostedAtUtc`
- `Reason`
- `AttachmentRefs`
- `JournalLineCount`
- `ApprovalCount`

### `manager_review_events.csv`
Required columns:
- `Id`
- `TenantId`
- `EntityType`
- `EntityId`
- `EventType`
- `ActorUserId`
- `ActorRoles`
- `OccurredAtUtc`
- `ReasonForChange`
- `BeforeJson`
- `AfterJson`
- `CorrelationId`
- `IpAddress`
- `UserAgent`

### `audit_trail.csv`
Required columns:
- `Id`
- `TenantId`
- `EntityType`
- `EntityId`
- `EventType`
- `ActorUserId`
- `ActorRoles`
- `OccurredAtUtc`
- `ReasonForChange`
- `BeforeJson`
- `AfterJson`
- `CorrelationId`
- `IpAddress`
- `UserAgent`

## 3) What Each Artifact Proves

- `timesheets_packet.csv`: Timecard lifecycle state evidence (draft/submit/approve/post), versioning, and correction activity.
- `labor_distribution.csv`: Labor charged by employee and charge code; supports objective-level labor traceability.
- `project_summary.csv`: Contract-level direct/indirect/unallowable totals for cost segregation review.
- `timesheet_compliance.csv`: Daily entry, timeliness, and correction compliance posture by employee.
- `clin_summary.csv`: Contract -> TaskOrder -> CLIN -> WBS -> ChargeCode rollup evidence.
- `indirect_rate_support.csv`: Indirect pool math inputs/outputs, versions, and final-rate review status.
- `applied_burden_summary.csv`: Burden application/rerate execution, base totals, and posted status.
- `trial_balance.csv`: GL balancing evidence for period.
- `general_journal.csv`: Posted journal-line detail by account.
- `subledger_gl_tieout.csv`: Reconciliation between subledgers and GL.
- `monthly_close_compliance.csv`: Period-by-period close cadence evidence, overdue status, close deadline aging, and posting activity count.
- `internal_audit_compliance.csv`: Periodic internal-audit compliance status including overdue posture and attestation completion.
- `internal_audit_cycles.csv`: Internal-audit checklist lifecycle details from draft through completion.
- `internal_audit_attestations.csv`: Explicit manager/compliance attestation records with statement and timestamps.
- `unallowable_costs.csv`: Source-level unallowable register demonstrating segregation and explicit exclusion basis for billing/claims.
- `invoices.csv`: Billing run outputs and invoice-level totals/status.
- `invoice_lines.csv`: Line-level bill composition by cost objective and cost element.
- `billed_cost_links.csv`: Traceability from billed line to source cost records.
- `billed_to_booked_reconciliation.csv`: Current-period booked-vs-billed tie-out and limit context.
- `adjusting_je_packet.csv`: Adjusting entry workflow evidence (maker-checker, reason, attachment, reversal linkage).
- `manager_review_events.csv`: Manager review/control-point activity across close, rates, billing, and adjusting.
- `audit_trail.csv`: Append-only event chronology with actor, event, reason, before/after payloads, and correlation metadata.

## 4) Acceptance Criteria for a Valid Evidence Package

A package is compliant with this spec when:

- All required CSV files listed above exist in one binder folder.
- Each file contains the required header columns for that artifact.
- Critical control artifacts are non-empty for active periods:
  - `audit_trail.csv`
  - `general_journal.csv`
  - `trial_balance.csv`
  - `subledger_gl_tieout.csv`
  - `monthly_close_compliance.csv`
  - `internal_audit_compliance.csv`
  - `internal_audit_cycles.csv`
  - `internal_audit_attestations.csv`
  - `unallowable_costs.csv`
  - `indirect_rate_support.csv`
  - `invoices.csv`
  - `adjusting_je_packet.csv`
- Values are internally consistent (examples):
  - `trial_balance.csv`: debits equal credits in aggregate.
  - `billed_to_booked_reconciliation.csv`: variance/status reflects billed vs booked logic.
  - `timesheets_packet.csv` and `timesheet_compliance.csv` align on timesheet counts and compliance signals.
