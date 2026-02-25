using GovConMoney.Domain.Enums;

namespace GovConMoney.Application.Models;

public sealed record AddTimesheetLineRequest(
    DateOnly WorkDate,
    Guid ChargeCodeId,
    int Minutes,
    CostType CostType,
    string Comment,
    TimesheetEntryType EntryType = TimesheetEntryType.Work);
public sealed record UpdateTimesheetLineRequest(
    DateOnly WorkDate,
    Guid ChargeCodeId,
    int Minutes,
    CostType CostType,
    string Comment,
    TimesheetEntryType EntryType = TimesheetEntryType.Work);
public sealed record AddTimesheetExpenseRequest(DateOnly ExpenseDate, Guid ChargeCodeId, decimal Amount, CostType CostType, string Category, string Description);
public sealed record UpdateTimesheetExpenseRequest(DateOnly ExpenseDate, Guid ChargeCodeId, decimal Amount, CostType CostType, string Category, string Description);
public sealed record AssignExpenseAccountingCategoryRequest(Guid ExpenseId, ExpenseAccountingCategory AccountingCategory, string? Reason);
public sealed record AddWorkNoteRequest(string Note);
public sealed record UpsertWeeklyStatusReportRequest(string Narrative);
public sealed record CreateTimesheetRequest(DateOnly PeriodStart, DateOnly PeriodEnd);
public sealed record SubmitTimesheetRequest(Guid TimesheetId, string Attestation);
public sealed record ApproveTimesheetRequest(Guid TimesheetId);
public sealed record RequestCorrectionRequest(Guid TimesheetId, string ReasonForChange);
public sealed record ApplyCorrectionRequest(Guid TimesheetId, Guid CorrectionRequestId, IReadOnlyList<AddTimesheetLineRequest> NewLines, string ReasonForChange);
public sealed record LaborDistributionRow(string Employee, string ChargeCode, int Minutes, decimal LaborDollars);
public sealed record ProjectSummaryRow(string ContractNumber, decimal DirectCost, decimal AllocatedIndirect, decimal Unallowable);
public sealed record TimesheetComplianceRow(string Employee, int MissingDays, int LateSubmissions, int CorrectionCount, int DailyEntryViolations);
public sealed record GeneralJournalRow(
    Guid JournalEntryId,
    DateOnly EntryDate,
    string Description,
    string AccountNumber,
    string AccountName,
    decimal Debit,
    decimal Credit);

public sealed record PayrollImportLineRequest(
    string EmployeeExternalId,
    decimal LaborAmount,
    decimal FringeAmount,
    decimal TaxAmount,
    decimal OtherAmount,
    string? Notes);

public sealed record PayrollImportBatchRequest(
    string ExternalBatchId,
    string SourceSystem,
    DateOnly PeriodStart,
    DateOnly PeriodEnd,
    string? SourceChecksum,
    string? Notes,
    IReadOnlyList<PayrollImportLineRequest> Lines);

public sealed record PayrollImportProfileUpsertRequest(
    Guid? ProfileId,
    string Name,
    string SourceSystem,
    string Delimiter,
    bool HasHeaderRow,
    string EmployeeExternalIdColumn,
    string LaborAmountColumn,
    string FringeAmountColumn,
    string TaxAmountColumn,
    string OtherAmountColumn,
    string? NotesColumn,
    string? RequiredHeadersCsv,
    bool RequireKnownEmployeeExternalId,
    bool DisallowDuplicateEmployeeExternalIds,
    bool RequirePositiveLaborAmount,
    bool IsActive);

public sealed record PayrollMappedImportBatchRequest(
    string ExternalBatchId,
    Guid PayrollImportProfileId,
    DateOnly PeriodStart,
    DateOnly PeriodEnd,
    string? SourceChecksum,
    string? Notes,
    string RawExtract);

public sealed record PayrollReconciliationRow(
    string EmployeeExternalId,
    string Employee,
    DateOnly PeriodStart,
    DateOnly PeriodEnd,
    decimal AccruedLabor,
    decimal PayrollLabor,
    decimal Variance,
    string Status);

public sealed record PayrollImportValidationIssue(
    int? LineNumber,
    string EmployeeExternalId,
    string Severity,
    string Message);

public sealed record ComputeIndirectRatesRequest(DateOnly PeriodStart, DateOnly PeriodEnd, bool IsFinal);
public sealed record ApplyIndirectBurdenRequest(DateOnly PeriodStart, DateOnly PeriodEnd, Guid? IndirectPoolId, Guid? RateCalculationId, bool PostToGeneralLedger);
public sealed record RerateIndirectBurdenRequest(DateOnly PeriodStart, DateOnly PeriodEnd, Guid IndirectPoolId, decimal NewRate, bool IsFinal, bool PostToGeneralLedger);

public sealed record IndirectRateSupportRow(
    Guid IndirectPoolId,
    string PoolName,
    Guid RateCalculationId,
    DateOnly PeriodStart,
    DateOnly PeriodEnd,
    decimal PoolCost,
    decimal AllocationBaseTotal,
    decimal Rate,
    int Version,
    bool IsFinal,
    DateTime CalculatedAtUtc,
    RateCalculationReviewStatus ReviewStatus,
    Guid? SubmittedForReviewByUserId,
    DateTime? SubmittedForReviewAtUtc,
    Guid? ReviewedByUserId,
    DateTime? ReviewedAtUtc,
    string? ReviewNote);

public sealed record AppliedBurdenSummaryRow(
    Guid RateCalculationId,
    Guid IndirectPoolId,
    string PoolName,
    DateOnly PeriodStart,
    DateOnly PeriodEnd,
    int EntryCount,
    decimal BaseAmountTotal,
    decimal BurdenAmountTotal,
    decimal Rate,
    bool IsAdjustment,
    bool PostedToGeneralLedger);

public sealed record TrialBalanceRow(
    string AccountNumber,
    string AccountName,
    decimal Debit,
    decimal Credit,
    decimal Net);

public sealed record SubledgerGlReconciliationRow(
    string Area,
    decimal SubledgerAmount,
    decimal GlAmount,
    decimal Variance,
    string Status);

public sealed record CloseValidationStepRow(
    string Step,
    bool Passed,
    string Detail);

public sealed record MonthlyCloseComplianceRow(
    Guid AccountingPeriodId,
    DateOnly StartDate,
    DateOnly EndDate,
    string Status,
    DateOnly CloseDeadline,
    int DaysPastEnd,
    int DaysPastCloseDeadline,
    int JournalEntryCount,
    bool IsOverdue);

public sealed record InternalAuditCycleRow(
    Guid InternalAuditCycleId,
    Guid AccountingPeriodId,
    DateOnly PeriodStart,
    DateOnly PeriodEnd,
    DateOnly DueDate,
    string Status,
    bool TieOutReviewCompleted,
    bool UnallowableReviewCompleted,
    bool BillingReviewCompleted,
    bool MonthlyCloseReviewCompleted,
    int AttestationCount,
    DateTime? SubmittedAtUtc,
    DateTime? CompletedAtUtc,
    string? Summary,
    string? Notes,
    string ReviewType = "",
    int ChecklistItemCount = 0,
    int ChecklistItemsCompleted = 0,
    int ChecklistItemsFailed = 0,
    DateTime? ApprovedAtUtc = null,
    DateTime? ClosedAtUtc = null,
    DateTime CreatedAtUtc = default);

public sealed record InternalAuditAttestationRow(
    Guid InternalAuditCycleId,
    Guid AttestationId,
    string AttestationType,
    Guid AttestedByUserId,
    string AttestedByRoles,
    DateTime AttestedAtUtc,
    string Statement,
    string? Notes);

public sealed record InternalAuditComplianceRow(
    Guid InternalAuditCycleId,
    DateOnly PeriodStart,
    DateOnly PeriodEnd,
    DateOnly DueDate,
    string Status,
    int DaysPastDue,
    bool IsOverdue,
    int RequiredAttestations,
    int ReceivedAttestations,
    bool AllChecklistItemsComplete,
    int OpenExceptionCount = 0);

public sealed record ComplianceReviewChecklistRow(
    Guid InternalAuditCycleId,
    Guid ChecklistItemId,
    string ClauseRef,
    string ControlName,
    string Result,
    string? Notes,
    DateTime UpdatedAtUtc,
    Guid UpdatedByUserId);

public sealed record ComplianceExceptionRow(
    Guid InternalAuditCycleId,
    Guid ComplianceExceptionId,
    Guid? ChecklistItemId,
    string Severity,
    string Category,
    string Description,
    string? RootCause,
    string? RemediationPlan,
    Guid? OwnerUserId,
    DateOnly? DueDate,
    string Status,
    DateTime? ResolvedAtUtc,
    Guid? ResolvedByUserId,
    string? ResolutionNotes);

public sealed record UpsertInternalAuditChecklistRequest(
    Guid InternalAuditCycleId,
    bool TieOutReviewCompleted,
    bool UnallowableReviewCompleted,
    bool BillingReviewCompleted,
    bool MonthlyCloseReviewCompleted,
    string? Notes);

public sealed record UpsertInternalAuditChecklistItemRequest(
    Guid InternalAuditCycleId,
    Guid ChecklistItemId,
    ComplianceChecklistResult Result,
    string? Notes);

public sealed record CreateInternalAuditCycleRequest(DateOnly PeriodStart, DateOnly PeriodEnd, InternalAuditReviewType ReviewType);
public sealed record AutoPopulateInternalAuditChecklistRequest(Guid InternalAuditCycleId);
public sealed record SubmitInternalAuditCycleRequest(Guid InternalAuditCycleId, string Summary);
public sealed record ApproveInternalAuditCycleRequest(Guid InternalAuditCycleId, string ApprovalNotes);
public sealed record RecordInternalAuditAttestationRequest(Guid InternalAuditCycleId, InternalAuditAttestationType AttestationType, string Statement, string? Notes);
public sealed record CompleteInternalAuditCycleRequest(Guid InternalAuditCycleId, string? Notes);
public sealed record ResolveComplianceExceptionRequest(Guid ComplianceExceptionId, string ResolutionNotes);
public sealed record AcceptComplianceRiskRequest(Guid ComplianceExceptionId, string ResolutionNotes);
public sealed record AddInternalAuditResolutionNoteRequest(Guid InternalAuditCycleId, string ResolutionNote);

public sealed record AdjustingJournalLineRequest(Guid AccountId, decimal Debit, decimal Credit);
public sealed record CreateAdjustingJournalEntryRequest(
    DateOnly EntryDate,
    string Description,
    string Reason,
    string? AttachmentRefs,
    IReadOnlyList<AdjustingJournalLineRequest> Lines);
public sealed record SubmitAdjustingJournalEntryRequest(Guid JournalEntryId, string Reason);
public sealed record ApproveAdjustingJournalEntryRequest(Guid JournalEntryId, string Reason, string? AttachmentRefs);
public sealed record PostAdjustingJournalEntryRequest(Guid JournalEntryId, string Reason);
public sealed record ReverseJournalEntryRequest(Guid JournalEntryId, DateOnly? ReversalDate, string Reason);

public sealed record UpsertBillingCeilingRequest(
    Guid ContractId,
    decimal FundedAmount,
    decimal CeilingAmount,
    DateOnly EffectiveStartDate,
    DateOnly EffectiveEndDate,
    bool IsActive);
public sealed record CreateBillingRunRequest(DateOnly PeriodStart, DateOnly PeriodEnd, Guid? ContractId, string? Notes);
public sealed record ApproveBillingRunRequest(Guid BillingRunId, string Reason);
public sealed record PostBillingRunRequest(Guid BillingRunId, string Reason);
public sealed record BillingRunSummaryRow(
    Guid BillingRunId,
    DateOnly PeriodStart,
    DateOnly PeriodEnd,
    string Status,
    int InvoiceCount,
    decimal TotalAmount,
    DateTime RunDateUtc);
public sealed record BillingReconciliationRow(
    Guid? ContractId,
    string ContractNumber,
    DateOnly PeriodStart,
    DateOnly PeriodEnd,
    decimal BookedAllowable,
    decimal BilledAmount,
    decimal Variance,
    string Status,
    decimal? BillingLimit,
    decimal? BilledToDate);

public sealed record ClinSummaryRow(
    Guid ContractId,
    string ContractNumber,
    Guid TaskOrderId,
    string TaskOrderNumber,
    Guid ClinId,
    string ClinNumber,
    Guid WbsNodeId,
    string WbsCode,
    Guid ChargeCodeId,
    string ChargeCode,
    CostType CostType,
    decimal LaborHours,
    decimal LaborDollars,
    decimal ExpenseDollars,
    decimal AppliedBurdenDollars,
    decimal TotalDollars);
