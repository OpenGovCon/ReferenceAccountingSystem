using GovConMoney.Application.Models;
using GovConMoney.Application.Services;
using GovConMoney.Domain.Entities;
using GovConMoney.Domain.Enums;
using GovConMoney.Infrastructure;
using GovConMoney.Infrastructure.Persistence;
using GovConMoney.Infrastructure.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;

var tests = new List<(string Name, Action Body)>
{
    ("Future dated time rejected", FutureDatedTimeRejected),
    ("Non-assigned charge code rejected", NonAssignedChargeCodeRejected),
    ("Submitted timesheet cannot be edited", SubmittedTimesheetCannotBeEdited),
    ("Draft line can be edited", DraftTimesheetLineCanBeEdited),
    ("Draft expense can be added and edited", DraftTimesheetExpenseCanBeAddedAndEdited),
    ("Draft expense can be deleted and voided", DraftTimesheetExpenseCanBeDeletedAndVoided),
    ("Submitted line edit is blocked", SubmittedTimesheetLineEditBlocked),
    ("Timesheet approval requires expense approvals", TimesheetApprovalRequiresExpenseApprovals),
    ("One time card per configured work period", OneTimeCardPerWorkPeriod),
    ("Duplicate period/cost center submission is flagged and blocked", DuplicateSubmissionIsFlaggedAndBlocked),
    ("Daily entry grace policy blocks late bulk entry on submit", DailyEntryGraceBlocksLateBulkEntryOnSubmit),
    ("Daily entry grace allows submission inside grace window", DailyEntryGraceAllowsRecentMissingDays),
    ("Timesheet compliance report includes daily entry violations", ComplianceReportIncludesDailyEntryViolations),
    ("Accountant can assign expense accounting category after submission", AccountantCanAssignExpenseAccountingCategory),
    ("Work notes and weekly status on draft", WorkNotesAndWeeklyStatusOnDraft),
    ("Work notes and weekly status blocked on submitted", WorkNotesAndWeeklyStatusBlockedOnSubmitted),
    ("Compliance hierarchy CRUD operations", ComplianceHierarchyCrudOperations),
    ("Compliance assignment create workflow", ComplianceAssignmentCreateWorkflow),
    ("Correction reason required and new immutable version", CorrectionCreatesNewVersionAndAudit),
    ("Supervisor cannot approve own timesheet", SupervisorCannotApproveOwnTimesheet),
    ("Tenant isolation blocks cross-tenant access", TenantIsolationPreventsCrossTenantAccess),
    ("Audit events for submit/approve/correct/user disable", AuditEventsAreCreated),
    ("Audit events are append-only", AuditEventsAreAppendOnly),
    ("Posted journal entries are immutable except reversal", PostedJournalEntryImmutabilityEnforced),
    ("Journal lines are append-only", JournalLineAppendOnlyEnforced),
    ("Out-of-window charging needs supervisor approval", OutOfWindowChargingRequiresApproval),
    ("Override approval sends notification to employee", OverrideApprovalSendsNotification),
    ("Daily overtime requires supervisor allowance approval", DailyOvertimeRequiresSupervisorAllowanceApproval),
    ("Closed accounting period blocks charging", ClosedAccountingPeriodBlocksCharging),
    ("Posting to closed accounting period is blocked", PostingToClosedAccountingPeriodBlocked),
    ("Payroll import reconciles to posted labor", PayrollImportReconcilesToPostedLabor),
    ("Payroll import profile mapping by header works", PayrollImportProfileMappingByHeaderWorks),
    ("Payroll strict profile validation blocks unmapped employees", PayrollStrictValidationBlocksUnmappedEmployees),
    ("Indirect rates compute apply rerate and post to GL", IndirectRatesComputeApplyRerateAndPost),
    ("Indirect base method direct labor hours drives rate and burden", IndirectBaseMethodDirectLaborHoursDrivesRateAndBurden),
    ("Final indirect rates require manager approval before apply", FinalIndirectRatesRequireManagerApprovalBeforeApply),
    ("Billing run approval requires manager role", BillingRunApprovalRequiresManagerRole),
    ("Period close requires manager role", PeriodCloseRequiresManagerRole),
    ("Monthly close compliance flags overdue open periods", MonthlyCloseComplianceFlagsOverdueOpenPeriods),
    ("Internal audit cycle requires checklist and attestations before completion", InternalAuditCycleRequiresChecklistAndAttestationsBeforeCompletion),
    ("Internal audit compliance report flags overdue incomplete cycles", InternalAuditComplianceReportFlagsOverdueIncompleteCycles),
    ("Compliance review requires attestation before submit", ComplianceReviewRequiresAttestationBeforeSubmit),
    ("Approver cannot be submitter (maker-checker enforced)", ApproverCannotBeSubmitterMakerCheckerEnforced),
    ("Failed checklist item generates exception", FailedChecklistItemGeneratesException),
    ("Review cannot close with open exceptions unless accepted risk by manager", ReviewCannotCloseWithOpenExceptionsUnlessAcceptedRiskByManager),
    ("Billing threshold routes approval to manager for high-value runs", BillingThresholdRoutesApprovalToManagerForHighValueRuns),
    ("Adjusting threshold requires manager co-sign only for high-value entries", AdjustingThresholdRequiresManagerCoSignOnlyForHighValueEntries),
    ("Subledger to GL reconciliation detects variance", SubledgerToGlReconciliationDetectsVariance),
    ("Adjusting JE maker-checker enforced", AdjustingJeMakerCheckerEnforced),
    ("Posted adjusting JE immutable except reversal", PostedAdjustingJeImmutableExceptReversal),
    ("Adjusting JE reversal links and balances", AdjustingJeReversalLinksAndBalances),
    ("Billing generation excludes unallowable costs", BillingGenerationExcludesUnallowables),
    ("Billing ceiling enforcement blocks overbilling", BillingCeilingEnforcementBlocksOverbilling),
    ("Billed-to-booked reconciliation ties to GL", BilledToBookedReconciliationTiesToGl),
    ("CLIN-tracked contract blocks unmapped charge codes", ClinTrackedContractBlocksUnmappedChargeCodes),
    ("CLIN summary rollup ties to posted labor", ClinSummaryRollupTiesToPostedLabor),
    ("Generate auditor binder evidence package", GenerateAuditBinderEvidencePackage)
};

var failures = new List<string>();
foreach (var (name, body) in tests)
{
    try
    {
        body();
        Console.WriteLine($"PASS: {name}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"FAIL: {name} - {ex.Message}");
        failures.Add(name);
    }
}

if (failures.Count > 0)
{
    Environment.ExitCode = 1;
    Console.WriteLine($"Failed tests: {string.Join(", ", failures)}");
}

static TestScope CreateScope()
{
    var options = new DbContextOptionsBuilder<GovConMoneyDbContext>()
        .UseInMemoryDatabase($"govconmoney-tests-{Guid.NewGuid():N}")
        .Options;
    var db = new GovConMoneyDbContext(options);
    var store = new InMemoryDataStore(db);
    var seed = SeedData.Initialize(store);
    var tenant = new TenantContextAccessor
    {
        TenantId = seed.TenantId,
        UserId = seed.TimeReporterUserId,
        Roles = new[] { "TimeReporter" }
    };

    var repo = new InMemoryRepository(db);
    var audit = new InMemoryAuditService(store, new HttpContextAccessor());
    var correlation = new CorrelationContext();
    var clock = new FixedClock(DateTime.UtcNow);
    var tx = new InMemoryTransaction(store);
    var notifications = new NotificationService(repo, tenant, clock);

    // Keep broad scenario tests stable: default seed now enforces hard daily-entry
    // and can block unrelated workflows when only a subset of days are entered.
    // Dedicated daily-entry tests override these values explicitly.
    var workPeriodConfig = store.WorkPeriodConfigurations.Single(x => x.TenantId == seed.TenantId);
    workPeriodConfig.DailyEntryRequired = true;
    workPeriodConfig.DailyEntryHardFail = true;
    workPeriodConfig.DailyEntryGraceDays = 14;
    workPeriodConfig.DailyEntryIncludeWeekends = false;
    store.SaveChanges();

    return new TestScope(store, seed, tenant, repo, audit, notifications, correlation, clock, tx);
}

static void FutureDatedTimeRejected()
{
    var s = CreateScope();
    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var t = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(DateOnly.FromDateTime(DateTime.UtcNow.AddDays(-2)), DateOnly.FromDateTime(DateTime.UtcNow.AddDays(5))));

    ExpectThrows<DomainRuleException>(() => timesheets.AddLine(t.Id,
        new AddTimesheetLineRequest(DateOnly.FromDateTime(DateTime.UtcNow.AddDays(1)), s.Seed.ChargeCodeId, 60, CostType.Direct, "future")));
}

static void NonAssignedChargeCodeRejected()
{
    var s = CreateScope();
    var charge = new ChargeCode { TenantId = s.Seed.TenantId, WbsNodeId = s.Store.WbsNodes.First().Id, Code = "UNASSIGNED", CostType = CostType.Direct };
    s.Store.ChargeCodes.Add(charge);
    s.Store.SaveChanges();

    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);
    var t = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(today.AddDays(-1), today));
    ExpectThrows<DomainRuleException>(() => timesheets.AddLine(t.Id, new AddTimesheetLineRequest(today, charge.Id, 60, CostType.Direct, "x")));
}

static void SubmittedTimesheetCannotBeEdited()
{
    var s = CreateScope();
    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);
    var t = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(today.AddDays(-1), today));
    timesheets.AddLine(t.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 60, CostType.Direct, "draft"));
    timesheets.Submit(new SubmitTimesheetRequest(t.Id, "I attest"));

    ExpectThrows<DomainRuleException>(() => timesheets.AddLine(t.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 30, CostType.Direct, "locked")));
}

static void DraftTimesheetLineCanBeEdited()
{
    var s = CreateScope();
    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);
    var t = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(today.AddDays(-1), today));
    var line = timesheets.AddLine(t.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 60, CostType.Direct, "initial"));

    var updated = timesheets.UpdateLine(t.Id, line.Id, new UpdateTimesheetLineRequest(today, s.Seed.ChargeCodeId, 90, CostType.Direct, "updated"));

    Assert(updated.Minutes == 90, "Edited line minutes not updated.");
    Assert(updated.Comment == "updated", "Edited line comment not updated.");
    Assert(s.Store.AuditEvents.Any(x => x.EntityType == "TimesheetLine" && x.EntityId == line.Id && x.EventType == EventType.UpdateDraft), "Edit should create update draft audit event.");
}

static void SubmittedTimesheetLineEditBlocked()
{
    var s = CreateScope();
    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);
    var t = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(today.AddDays(-1), today));
    var line = timesheets.AddLine(t.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 60, CostType.Direct, "draft"));
    timesheets.Submit(new SubmitTimesheetRequest(t.Id, "attest"));

    ExpectThrows<DomainRuleException>(() => timesheets.UpdateLine(t.Id, line.Id, new UpdateTimesheetLineRequest(today, s.Seed.ChargeCodeId, 30, CostType.Direct, "locked")));
}

static void DraftTimesheetExpenseCanBeAddedAndEdited()
{
    var s = CreateScope();
    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);
    var t = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(today.AddDays(-1), today));

    var expense = timesheets.AddExpense(t.Id, new AddTimesheetExpenseRequest(today, s.Seed.ChargeCodeId, 125.50m, CostType.Direct, "Travel", "Mileage"));
    var updated = timesheets.UpdateExpense(t.Id, expense.Id, new UpdateTimesheetExpenseRequest(today, s.Seed.ChargeCodeId, 140.00m, CostType.Direct, "Travel", "Mileage updated"));

    Assert(updated.Amount == 140.00m, "Expense amount not updated.");
    Assert(updated.Description == "Mileage updated", "Expense description not updated.");
    Assert(s.Store.AuditEvents.Any(x => x.EntityType == "TimesheetExpense" && x.EntityId == expense.Id && x.EventType == EventType.UpdateDraft), "Expense audit missing.");
}

static void DraftTimesheetExpenseCanBeDeletedAndVoided()
{
    var s = CreateScope();
    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);
    var t = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(today.AddDays(-1), today));

    var toDelete = timesheets.AddExpense(t.Id, new AddTimesheetExpenseRequest(today, s.Seed.ChargeCodeId, 80m, CostType.Direct, "Meals", "Lunch"));
    timesheets.DeleteExpense(t.Id, toDelete.Id);
    Assert(s.Store.TimesheetExpenses.Any(x => x.Id == toDelete.Id && x.Status == ExpenseStatus.Voided), "Expense delete should void the draft expense.");

    var toVoid = timesheets.AddExpense(t.Id, new AddTimesheetExpenseRequest(today, s.Seed.ChargeCodeId, 50m, CostType.Direct, "Travel", "Taxi"));
    var voided = timesheets.VoidExpense(t.Id, toVoid.Id, "Duplicate receipt");
    Assert(voided.Status == ExpenseStatus.Voided, "Expense should be voided.");
    Assert(voided.VoidReason == "Duplicate receipt", "Void reason not stored.");
}

static void TimesheetApprovalRequiresExpenseApprovals()
{
    var s = CreateScope();
    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);

    var t = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(today.AddDays(-1), today));
    timesheets.AddLine(t.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 60, CostType.Direct, "work"));
    var expense = timesheets.AddExpense(t.Id, new AddTimesheetExpenseRequest(today, s.Seed.ChargeCodeId, 200m, CostType.Direct, "Travel", "Mileage"));
    timesheets.Submit(new SubmitTimesheetRequest(t.Id, "attest"));

    s.TenantContext.UserId = s.Seed.SupervisorUserId;
    s.TenantContext.Roles = new[] { "Supervisor" };

    ExpectThrows<DomainRuleException>(() => timesheets.Approve(new ApproveTimesheetRequest(t.Id)));
    timesheets.ApproveExpense(t.Id, expense.Id);
    timesheets.Approve(new ApproveTimesheetRequest(t.Id));

    var approved = s.Store.Timesheets.Single(x => x.Id == t.Id);
    Assert(approved.Status == TimesheetStatus.Approved, "Timesheet should be approved after expenses are approved.");
}

static void OneTimeCardPerWorkPeriod()
{
    var s = CreateScope();
    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);
    var start = today.AddDays(-(((int)today.DayOfWeek + 6) % 7));
    var end = start.AddDays(6);

    timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(start, end));
    ExpectThrows<DomainRuleException>(() => timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(start.AddDays(1), end)));
}

static void DuplicateSubmissionIsFlaggedAndBlocked()
{
    var s = CreateScope();
    var config = s.Store.WorkPeriodConfigurations.Single(x => x.TenantId == s.Seed.TenantId);
    config.DailyEntryGraceDays = 14;
    s.Store.SaveChanges();

    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);
    var start = today.AddDays(-(((int)today.DayOfWeek + 6) % 7));
    var end = start.AddDays(6);

    var submitted = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(start, end));
    timesheets.AddLine(submitted.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 60, CostType.Direct, "baseline"));
    timesheets.Submit(new SubmitTimesheetRequest(submitted.Id, "attest"));

    var duplicate = new Timesheet
    {
        TenantId = s.Seed.TenantId,
        UserId = s.Seed.TimeReporterUserId,
        PeriodStart = start.AddDays(1),
        PeriodEnd = end,
        Status = TimesheetStatus.Draft
    };
    s.Repository.Add(duplicate);
    s.Repository.Add(new TimesheetLine
    {
        TenantId = s.Seed.TenantId,
        TimesheetId = duplicate.Id,
        WorkDate = today,
        ChargeCodeId = s.Seed.ChargeCodeId,
        Minutes = 30,
        CostType = CostType.Direct,
        Comment = "dup"
    });

    ExpectThrows<DomainRuleException>(() => timesheets.Submit(new SubmitTimesheetRequest(duplicate.Id, "attest")));
    var reloaded = s.Store.Timesheets.Single(x => x.Id == duplicate.Id);
    Assert(reloaded.IsComplianceFlagged, "Duplicate submission should flag the time card.");
}

static void DailyEntryGraceBlocksLateBulkEntryOnSubmit()
{
    var s = CreateScope();
    var config = s.Store.WorkPeriodConfigurations.Single(x => x.TenantId == s.Seed.TenantId);
    config.DailyEntryRequired = true;
    config.DailyEntryHardFail = true;
    config.DailyEntryGraceDays = 1;
    config.DailyEntryIncludeWeekends = false;
    s.Store.SaveChanges();

    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);
    var start = today.AddDays(-6);
    var end = today;
    var t = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(start, end));
    timesheets.AddLine(t.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 60, CostType.Direct, "single day"));

    ExpectThrows<DomainRuleException>(() => timesheets.Submit(new SubmitTimesheetRequest(t.Id, "attest")));
    var flagged = s.Store.Timesheets.Single(x => x.Id == t.Id);
    Assert(flagged.IsComplianceFlagged, "Daily entry violation should flag the time card.");
    Assert((flagged.ComplianceIssuesJson ?? string.Empty).Contains("Daily entry requirement violated"), "Daily entry violation should be persisted in compliance issues.");
}

static void DailyEntryGraceAllowsRecentMissingDays()
{
    var s = CreateScope();
    var config = s.Store.WorkPeriodConfigurations.Single(x => x.TenantId == s.Seed.TenantId);
    config.DailyEntryRequired = true;
    config.DailyEntryHardFail = true;
    config.DailyEntryGraceDays = 14;
    config.DailyEntryIncludeWeekends = false;
    s.Store.SaveChanges();

    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);
    var start = today.AddDays(-6);
    var end = today;
    var t = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(start, end));
    timesheets.AddLine(t.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 60, CostType.Direct, "inside grace"));

    timesheets.Submit(new SubmitTimesheetRequest(t.Id, "attest"));
    var submitted = s.Store.Timesheets.Single(x => x.Id == t.Id);
    Assert(submitted.Status == TimesheetStatus.Submitted, "Submission should succeed when missing days are inside grace window.");
}

static void ComplianceReportIncludesDailyEntryViolations()
{
    var s = CreateScope();
    var config = s.Store.WorkPeriodConfigurations.Single(x => x.TenantId == s.Seed.TenantId);
    config.DailyEntryRequired = true;
    config.DailyEntryHardFail = true;
    config.DailyEntryGraceDays = 1;
    config.DailyEntryIncludeWeekends = false;
    s.Store.SaveChanges();

    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var reporting = new ReportingService(s.Repository, s.TenantContext);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);
    var start = today.AddDays(-6);
    var end = today;
    var t = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(start, end));
    timesheets.AddLine(t.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 60, CostType.Direct, "single day"));

    ExpectThrows<DomainRuleException>(() => timesheets.Submit(new SubmitTimesheetRequest(t.Id, "attest")));
    var row = reporting.TimesheetCompliance().Single(x => x.Employee == "timereporter");
    Assert(row.DailyEntryViolations > 0, "Timesheet compliance report should surface daily entry violations.");
}

static void AccountantCanAssignExpenseAccountingCategory()
{
    var s = CreateScope();
    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);
    var t = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(today.AddDays(-1), today));
    var expense = timesheets.AddExpense(t.Id, new AddTimesheetExpenseRequest(today, s.Seed.ChargeCodeId, 110m, CostType.Direct, "Travel", "Lodging"));

    ExpectThrows<DomainRuleException>(() => timesheets.AssignExpenseAccountingCategory(expense.Id, ExpenseAccountingCategory.GAndA, "pre-submit"));

    timesheets.AddLine(t.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 60, CostType.Direct, "work"));
    timesheets.Submit(new SubmitTimesheetRequest(t.Id, "attest"));

    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };

    var updated = timesheets.AssignExpenseAccountingCategory(expense.Id, ExpenseAccountingCategory.GAndA, "classified by accounting");
    Assert(updated.AccountingCategory == ExpenseAccountingCategory.GAndA, "Accounting category assignment failed.");
}

static void WorkNotesAndWeeklyStatusOnDraft()
{
    var s = CreateScope();
    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);
    var t = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(today.AddDays(-6), today));

    var note = timesheets.AddWorkNote(t.Id, new AddWorkNoteRequest("Completed integration for invoice import."));
    var status = timesheets.UpsertWeeklyStatusReport(t.Id, new UpsertWeeklyStatusReportRequest("Delivered invoice import, resolved 2 defects, preparing UAT script."));

    Assert(!string.IsNullOrWhiteSpace(note.Note), "Work note should be stored.");
    Assert(status.TimesheetId == t.Id, "Weekly status should be tied to timesheet.");
    Assert(s.Store.AuditEvents.Any(x => x.EntityType == "TimesheetWorkNote" && x.EntityId == note.Id), "Work note audit missing.");
    Assert(s.Store.AuditEvents.Any(x => x.EntityType == "WeeklyStatusReport" && x.EntityId == status.Id), "Weekly status audit missing.");
}

static void WorkNotesAndWeeklyStatusBlockedOnSubmitted()
{
    var s = CreateScope();
    var config = s.Store.WorkPeriodConfigurations.Single(x => x.TenantId == s.Seed.TenantId);
    config.DailyEntryGraceDays = 14;
    s.Store.SaveChanges();

    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);
    var t = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(today.AddDays(-6), today));
    timesheets.AddLine(t.Id, new AddTimesheetLineRequest(today.AddDays(-1), s.Seed.ChargeCodeId, 60, CostType.Direct, "work"));
    timesheets.Submit(new SubmitTimesheetRequest(t.Id, "attest"));

    ExpectThrows<DomainRuleException>(() => timesheets.AddWorkNote(t.Id, new AddWorkNoteRequest("late note")));
    ExpectThrows<DomainRuleException>(() => timesheets.UpsertWeeklyStatusReport(t.Id, new UpsertWeeklyStatusReportRequest("late status")));
}

static void ComplianceHierarchyCrudOperations()
{
    var s = CreateScope();
    var compliance = new ComplianceService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);

    var contract = compliance.CreateContract("C-CRUD-1", "CRUD Contract", 1000m, ContractType.FixedValue);
    contract = compliance.UpdateContract(contract.Id, "C-CRUD-1U", "CRUD Contract Updated", 1500m, ContractType.Idiq);
    Assert(contract.ContractNumber == "C-CRUD-1U", "Contract update failed.");

    var taskOrder = compliance.CreateTaskOrder(contract.Id, "TO-CRUD", 500m);
    taskOrder = compliance.UpdateTaskOrder(taskOrder.Id, "TO-CRUD-U", 600m);
    Assert(taskOrder.Number == "TO-CRUD-U", "Task order update failed.");

    var clin = compliance.CreateClin(taskOrder.Id, "0001ZZ");
    clin = compliance.UpdateClin(clin.Id, "0001YY");
    Assert(clin.Number == "0001YY", "CLIN update failed.");

    var wbs = compliance.CreateWbs(clin.Id, "9.9", null);
    wbs = compliance.UpdateWbs(wbs.Id, "9.10", null);
    Assert(wbs.Code == "9.10", "WBS update failed.");

    var chargeCode = compliance.CreateChargeCode(wbs.Id, "CC-CRUD", CostType.Direct);
    chargeCode = compliance.UpdateChargeCode(chargeCode.Id, "CC-CRUD-U", CostType.Indirect);
    Assert(chargeCode.Code == "CC-CRUD-U", "Charge code update failed.");

    var optionYear = compliance.AddOptionYear(contract.Id, DateOnly.FromDateTime(DateTime.UtcNow.AddYears(1)), DateOnly.FromDateTime(DateTime.UtcNow.AddYears(2).AddDays(-1)));
    optionYear = compliance.UpdateOptionYear(optionYear.Id, optionYear.StartDate, optionYear.EndDate.AddDays(10));
    Assert(optionYear.EndDate > optionYear.StartDate, "Option year update failed.");
    compliance.DeleteOptionYear(optionYear.Id);

    compliance.DeleteChargeCode(chargeCode.Id);
    compliance.DeleteWbs(wbs.Id);
    compliance.DeleteClin(clin.Id);
    compliance.DeleteTaskOrder(taskOrder.Id);
    compliance.DeleteContract(contract.Id);

    Assert(s.Store.Contracts.IgnoreQueryFilters().Any(x => x.Id == contract.Id && x.IsDeleted), "Contract soft delete failed.");
}

static void ComplianceAssignmentCreateWorkflow()
{
    var s = CreateScope();
    var compliance = new ComplianceService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);

    var assignment = compliance.AssignUserToChargeCode(s.Seed.TimeReporterUserId, s.Seed.ChargeCodeId, today, today.AddDays(14), true);

    Assert(s.Store.Assignments.Any(x => x.Id == assignment.Id), "Assignment was not created.");
}

static void CorrectionCreatesNewVersionAndAudit()
{
    var s = CreateScope();
    var config = s.Store.WorkPeriodConfigurations.Single(x => x.TenantId == s.Seed.TenantId);
    config.DailyEntryGraceDays = 14;
    s.Store.SaveChanges();

    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);
    var t = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(today.AddDays(-3), today));
    timesheets.AddLine(t.Id, new AddTimesheetLineRequest(today.AddDays(-1), s.Seed.ChargeCodeId, 60, CostType.Direct, "v1"));
    timesheets.Submit(new SubmitTimesheetRequest(t.Id, "submit"));

    ExpectThrows<DomainRuleException>(() => timesheets.RequestCorrection(new RequestCorrectionRequest(t.Id, "")));

    var correction = timesheets.RequestCorrection(new RequestCorrectionRequest(t.Id, "Payroll mismatch"));
    var newSheet = timesheets.ApplyCorrection(new ApplyCorrectionRequest(
        t.Id,
        correction.Id,
        [new AddTimesheetLineRequest(today.AddDays(-1), s.Seed.ChargeCodeId, 120, CostType.Direct, "v2")],
        "Payroll mismatch"));

    Assert(newSheet.VersionNumber == 2, "New timesheet version should increment.");
    Assert(s.Store.TimesheetVersions.Count() == 1, "Original snapshot should be preserved.");
    Assert(s.Store.AuditEvents.Any(x => x.EventType == EventType.Correct), "Correction audit event missing.");
}

static void SupervisorCannotApproveOwnTimesheet()
{
    var s = CreateScope();
    s.TenantContext.UserId = s.Seed.SupervisorUserId;
    s.TenantContext.Roles = new[] { "Supervisor" };

    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);

    s.Store.Assignments.Add(new Assignment
    {
        TenantId = s.Seed.TenantId,
        UserId = s.Seed.SupervisorUserId,
        ChargeCodeId = s.Seed.ChargeCodeId,
        EffectiveStartDate = today.AddDays(-30),
        EffectiveEndDate = today.AddDays(30)
    });
    s.Store.SaveChanges();

    var sheet = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(today.AddDays(-1), today));
    timesheets.AddLine(sheet.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 60, CostType.Direct, "self"));
    timesheets.Submit(new SubmitTimesheetRequest(sheet.Id, "submit"));

    ExpectThrows<DomainRuleException>(() => timesheets.Approve(new ApproveTimesheetRequest(sheet.Id)));
}

static void TenantIsolationPreventsCrossTenantAccess()
{
    var s = CreateScope();
    var otherTenant = new Tenant { Name = "Other" };
    s.Store.Tenants.Add(otherTenant);

    var otherUser = new AppUser { TenantId = otherTenant.Id, UserName = "other", Email = "o@x" };
    otherUser.Roles.Add("TimeReporter");
    s.Store.Users.Add(otherUser);
    s.Store.SaveChanges();

    Assert(!s.Repository.Query<AppUser>(s.Seed.TenantId).Any(x => x.Id == otherUser.Id), "Cross-tenant user should not be visible.");
}

static void AuditEventsAreCreated()
{
    var s = CreateScope();
    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);

    var sheet = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(today.AddDays(-1), today));
    timesheets.AddLine(sheet.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 60, CostType.Direct, "work"));
    timesheets.Submit(new SubmitTimesheetRequest(sheet.Id, "attest"));

    s.TenantContext.UserId = s.Seed.SupervisorUserId;
    s.TenantContext.Roles = new[] { "Supervisor" };
    timesheets.Approve(new ApproveTimesheetRequest(sheet.Id));

    var correction = timesheets.RequestCorrection(new RequestCorrectionRequest(sheet.Id, "adjust"));
    s.TenantContext.UserId = s.Seed.TimeReporterUserId;
    s.TenantContext.Roles = new[] { "TimeReporter" };
    timesheets.ApplyCorrection(new ApplyCorrectionRequest(sheet.Id, correction.Id,
        [new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 90, CostType.Direct, "adjusted")], "adjust"));

    var admin = s.Store.Users.Single(x => x.Id == s.Seed.AdminUserId);
    admin.IsDisabled = true;
    s.Audit.Record(new AuditEvent
    {
        TenantId = s.Seed.TenantId,
        EntityType = "AppUser",
        EntityId = admin.Id,
        EventType = EventType.DisableUser,
        ActorUserId = s.Seed.AdminUserId,
        ActorRoles = "Admin",
        CorrelationId = s.Correlation.CorrelationId
    });

    Assert(s.Store.AuditEvents.Any(x => x.EventType == EventType.Submit), "Submit audit missing.");
    Assert(s.Store.AuditEvents.Any(x => x.EventType == EventType.Approve), "Approve audit missing.");
    Assert(s.Store.AuditEvents.Any(x => x.EventType == EventType.Correct), "Correct audit missing.");
    Assert(s.Store.AuditEvents.Any(x => x.EventType == EventType.DisableUser), "Disable user audit missing.");

    var critical = s.Store.AuditEvents
        .ToList()
        .Where(x => x.EventType == EventType.Submit || x.EventType == EventType.Approve || x.EventType == EventType.Correct || x.EventType == EventType.DisableUser)
        .ToList();
    Assert(critical.Count >= 4, "Expected critical audit events were not all recorded.");
    Assert(critical.All(x => x.EntityId != Guid.Empty), "Critical audit events must include entity id.");
    Assert(critical.All(x => !string.IsNullOrWhiteSpace(x.EntityType)), "Critical audit events must include entity type.");
    Assert(critical.All(x => x.ActorUserId != Guid.Empty), "Critical audit events must include actor id.");
    Assert(critical.All(x => x.OccurredAtUtc != default), "Critical audit events must include timestamp.");
}

static void AuditEventsAreAppendOnly()
{
    var s = CreateScope();
    s.Audit.Record(new AuditEvent
    {
        TenantId = s.Seed.TenantId,
        EntityType = "TestEntity",
        EntityId = Guid.NewGuid(),
        EventType = EventType.Create,
        ActorUserId = s.Seed.AdminUserId,
        ActorRoles = "Admin",
        CorrelationId = s.Correlation.CorrelationId
    });

    var auditEvent = s.Store.AuditEvents.First();
    auditEvent.UserAgent = "tampered-agent";
    ExpectThrows<InvalidOperationException>(() => s.Store.SaveChanges());
}

static void PostedJournalEntryImmutabilityEnforced()
{
    var s = CreateScope();
    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };
    var accounting = new AccountingService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    accounting.PostApprovedTimeCardsToLedger();
    var workflow = new JournalEntryWorkflowService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction, s.Notifications);
    var account5000 = s.Store.ChartOfAccounts.Single(x => x.AccountNumber == "5000");
    var account2100 = s.Store.ChartOfAccounts.Single(x => x.AccountNumber == "2100");

    var draft = workflow.CreateAdjustingEntry(new CreateAdjustingJournalEntryRequest(
        DateOnly.FromDateTime(DateTime.UtcNow),
        "Immutability test JE",
        "test",
        null,
        [
            new AdjustingJournalLineRequest(account5000.Id, 42m, 0m),
            new AdjustingJournalLineRequest(account2100.Id, 0m, 42m)
        ]));
    workflow.SubmitAdjustingEntry(new SubmitAdjustingJournalEntryRequest(draft.Id, "submit"));

    s.TenantContext.UserId = s.Seed.ManagerUserId;
    s.TenantContext.Roles = new[] { "Manager" };
    workflow.ApproveAdjustingEntry(new ApproveAdjustingJournalEntryRequest(draft.Id, "approve", null));
    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };
    var posted = workflow.PostApprovedEntry(new PostAdjustingJournalEntryRequest(draft.Id, "post"));

    posted.Description = "tampered description";
    ExpectThrows<InvalidOperationException>(() => s.Store.SaveChanges());
}

static void JournalLineAppendOnlyEnforced()
{
    var s = CreateScope();
    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var accounting = new AccountingService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);
    var sheet = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(today.AddDays(-1), today));
    timesheets.AddLine(sheet.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 60, CostType.Direct, "line"));
    timesheets.Submit(new SubmitTimesheetRequest(sheet.Id, "attest"));
    s.TenantContext.UserId = s.Seed.SupervisorUserId;
    s.TenantContext.Roles = new[] { "Supervisor" };
    timesheets.Approve(new ApproveTimesheetRequest(sheet.Id));
    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };
    accounting.PostApprovedTimeCardsToLedger();

    var postedLine = s.Store.JournalLines.First();
    s.Store.JournalLines.Remove(postedLine);
    ExpectThrows<InvalidOperationException>(() => s.Store.SaveChanges());
}

static void OutOfWindowChargingRequiresApproval()
{
    var s = CreateScope();
    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var compliance = new ComplianceService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);

    var today = DateOnly.FromDateTime(DateTime.UtcNow);
    var outsideDate = today.AddDays(-90);

    s.Store.Assignments.RemoveRange(s.Store.Assignments);
    s.Store.Assignments.Add(new Assignment
    {
        TenantId = s.Seed.TenantId,
        UserId = s.Seed.TimeReporterUserId,
        ChargeCodeId = s.Seed.ChargeCodeId,
        EffectiveStartDate = today.AddDays(-10),
        EffectiveEndDate = today.AddDays(10),
        SupervisorOverrideAllowed = true
    });
    s.Store.SaveChanges();

    var t = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(outsideDate, outsideDate));

    ExpectThrows<DomainRuleException>(() => timesheets.AddLine(t.Id, new AddTimesheetLineRequest(outsideDate, s.Seed.ChargeCodeId, 60, CostType.Direct, "outside")));

    s.TenantContext.UserId = s.Seed.SupervisorUserId;
    s.TenantContext.Roles = new[] { "Supervisor" };
    compliance.ApproveOutOfWindowCharge(s.Seed.TimeReporterUserId, s.Seed.ChargeCodeId, outsideDate, "retro approval");

    s.TenantContext.UserId = s.Seed.TimeReporterUserId;
    s.TenantContext.Roles = new[] { "TimeReporter" };
    timesheets.AddLine(t.Id, new AddTimesheetLineRequest(outsideDate, s.Seed.ChargeCodeId, 60, CostType.Direct, "approved outside"));
}

static void OverrideApprovalSendsNotification()
{
    var s = CreateScope();
    var compliance = new ComplianceService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction, s.Notifications);
    var today = DateOnly.FromDateTime(DateTime.UtcNow).AddDays(-30);

    s.TenantContext.UserId = s.Seed.SupervisorUserId;
    s.TenantContext.Roles = new[] { "Supervisor" };
    compliance.ApproveOutOfWindowCharge(s.Seed.TimeReporterUserId, s.Seed.ChargeCodeId, today, "Needed for payroll correction");

    s.TenantContext.UserId = s.Seed.TimeReporterUserId;
    s.TenantContext.Roles = new[] { "TimeReporter" };
    var inbox = s.Notifications.GetInbox(false, 10);
    Assert(inbox.Any(x => x.Title.Contains("Out-of-Window Charge Approved", StringComparison.OrdinalIgnoreCase)), "Employee notification was not created.");
}

static void DailyOvertimeRequiresSupervisorAllowanceApproval()
{
    var s = CreateScope();
    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var compliance = new ComplianceService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction, s.Notifications);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);

    var t = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(today, today));
    timesheets.AddLine(t.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 300, CostType.Direct, "morning work"));
    timesheets.AddLine(t.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 240, CostType.Direct, "afternoon work"));

    ExpectThrows<DomainRuleException>(() => timesheets.Submit(new SubmitTimesheetRequest(t.Id, "attest")));
    var flagged = s.Store.Timesheets.Single(x => x.Id == t.Id);
    Assert(flagged.IsComplianceFlagged, "Overtime authorization gap should flag the time card.");
    Assert((flagged.ComplianceIssuesJson ?? string.Empty).Contains("Overtime authorization required"), "Overtime authorization issue should be persisted.");

    s.TenantContext.UserId = s.Seed.SupervisorUserId;
    s.TenantContext.Roles = new[] { "Supervisor" };
    compliance.ApproveOvertimeAllowance(s.Seed.TimeReporterUserId, today, 60, "Approved for project crunch.");

    s.TenantContext.UserId = s.Seed.TimeReporterUserId;
    s.TenantContext.Roles = new[] { "TimeReporter" };
    timesheets.Submit(new SubmitTimesheetRequest(t.Id, "attest"));

    var submitted = s.Store.Timesheets.Single(x => x.Id == t.Id);
    Assert(submitted.Status == TimesheetStatus.Submitted, "Submission should succeed after overtime allowance approval.");
    Assert(s.Store.OvertimeAllowanceApprovals.Any(x => x.UserId == s.Seed.TimeReporterUserId && x.WorkDate == today), "Overtime allowance approval should be stored.");
}

static void ClosedAccountingPeriodBlocksCharging()
{
    var s = CreateScope();
    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);

    s.Store.AccountingPeriods.RemoveRange(s.Store.AccountingPeriods);
    s.Store.AccountingPeriods.Add(new AccountingPeriod
    {
        TenantId = s.Seed.TenantId,
        StartDate = today.AddDays(-2),
        EndDate = today,
        Status = AccountingPeriodStatus.Closed
    });
    s.Store.SaveChanges();

    var t = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(today.AddDays(-1), today));
    ExpectThrows<DomainRuleException>(() => timesheets.AddLine(t.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 60, CostType.Direct, "closed")));
}

static void PostingToClosedAccountingPeriodBlocked()
{
    var s = CreateScope();
    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var accounting = new AccountingService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);

    s.Store.AccountingPeriods.RemoveRange(s.Store.AccountingPeriods);
    s.Store.AccountingPeriods.Add(new AccountingPeriod
    {
        TenantId = s.Seed.TenantId,
        StartDate = today.AddDays(-7),
        EndDate = today.AddDays(7),
        Status = AccountingPeriodStatus.Closed
    });
    s.Store.SaveChanges();

    var t = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(today.AddDays(-1), today));
    s.Store.AccountingPeriods.RemoveRange(s.Store.AccountingPeriods);
    s.Store.AccountingPeriods.Add(new AccountingPeriod
    {
        TenantId = s.Seed.TenantId,
        StartDate = today.AddDays(-7),
        EndDate = today.AddDays(7),
        Status = AccountingPeriodStatus.Open
    });
    s.Store.SaveChanges();

    timesheets.AddLine(t.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 60, CostType.Direct, "work"));
    timesheets.Submit(new SubmitTimesheetRequest(t.Id, "attest"));
    s.TenantContext.UserId = s.Seed.SupervisorUserId;
    s.TenantContext.Roles = new[] { "Supervisor" };
    timesheets.Approve(new ApproveTimesheetRequest(t.Id));

    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };
    var period = s.Store.AccountingPeriods.Single();
    period.Status = AccountingPeriodStatus.Closed;
    s.Store.SaveChanges();

    ExpectThrows<DomainRuleException>(() => accounting.PostApprovedTimeCardsToLedger());
}

static void PayrollImportReconcilesToPostedLabor()
{
    var s = CreateScope();
    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var accounting = new AccountingService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var payroll = new PayrollService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);

    var sheet = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(today.AddDays(-1), today));
    timesheets.AddLine(sheet.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 60, CostType.Direct, "work"));
    timesheets.Submit(new SubmitTimesheetRequest(sheet.Id, "attest"));

    s.TenantContext.UserId = s.Seed.SupervisorUserId;
    s.TenantContext.Roles = new[] { "Supervisor" };
    timesheets.Approve(new ApproveTimesheetRequest(sheet.Id));

    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };
    accounting.PostApprovedTimeCardsToLedger();

    var reporter = s.Store.Users.Single(x => x.Id == s.Seed.TimeReporterUserId);
    payroll.ImportBatch(new PayrollImportBatchRequest(
        "BATCH-001",
        "Manual",
        sheet.PeriodStart,
        sheet.PeriodEnd,
        null,
        "test",
        [new PayrollImportLineRequest(reporter.EmployeeExternalId, 55m, 0m, 0m, 0m, "line")]));

    var rows = payroll.Reconciliation(sheet.PeriodStart, sheet.PeriodEnd);
    Assert(rows.Any(x => x.EmployeeExternalId == reporter.EmployeeExternalId && x.Status == "Matched"), "Payroll reconciliation did not match posted labor.");
}

static void PayrollImportProfileMappingByHeaderWorks()
{
    var s = CreateScope();
    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var accounting = new AccountingService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var payroll = new PayrollService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);

    var sheet = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(today.AddDays(-1), today));
    timesheets.AddLine(sheet.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 60, CostType.Direct, "work"));
    timesheets.Submit(new SubmitTimesheetRequest(sheet.Id, "attest"));

    s.TenantContext.UserId = s.Seed.SupervisorUserId;
    s.TenantContext.Roles = new[] { "Supervisor" };
    timesheets.Approve(new ApproveTimesheetRequest(sheet.Id));

    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };
    accounting.PostApprovedTimeCardsToLedger();

    var reporter = s.Store.Users.Single(x => x.Id == s.Seed.TimeReporterUserId);
    var profile = payroll.UpsertImportProfile(new PayrollImportProfileUpsertRequest(
        null,
        "Provider A",
        "ProviderA",
        ",",
        true,
        "EmpId",
        "Labor",
        "Fringe",
        "Tax",
        "Other",
        "Memo",
        "EmpId,Labor,Tax",
        true,
        true,
        true,
        true));

    payroll.ImportBatchFromMappedExtract(new PayrollMappedImportBatchRequest(
        "BATCH-002",
        profile.Id,
        sheet.PeriodStart,
        sheet.PeriodEnd,
        null,
        "header-mapped test",
        $"EmpId,Labor,Fringe,Tax,Other,Memo\n{reporter.EmployeeExternalId},55.00,0,0,0,line"));

    var rows = payroll.Reconciliation(sheet.PeriodStart, sheet.PeriodEnd);
    Assert(rows.Any(x => x.EmployeeExternalId == reporter.EmployeeExternalId && x.Status == "Matched"), "Header-mapped payroll reconciliation did not match posted labor.");
}

static void PayrollStrictValidationBlocksUnmappedEmployees()
{
    var s = CreateScope();
    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };

    var payroll = new PayrollService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var profile = payroll.UpsertImportProfile(new PayrollImportProfileUpsertRequest(
        null,
        "Strict Validation",
        "PayrollExtract",
        ",",
        true,
        "EmployeeId",
        "Labor",
        "Fringe",
        "Tax",
        "Other",
        "Notes",
        "EmployeeId,Labor",
        true,
        true,
        true,
        true));

    var parsed = payroll.ParseMappedExtract(profile.Id, "EmployeeId,Labor,Fringe,Tax,Other,Notes\nEMP-NOT-MAPPED,10,0,0,0,missing");
    var issues = payroll.ValidateImportLines(parsed.Lines, profile);

    Assert(issues.Any(x => x.Severity == "Error"), "Strict profile should generate error for unmapped employee.");
    ExpectThrows<DomainRuleException>(() => PayrollService.EnsureNoBlockingValidationIssues(issues));
}

static void IndirectRatesComputeApplyRerateAndPost()
{
    var s = CreateScope();
    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var accounting = new AccountingService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var indirect = new IndirectRateService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction, accounting);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);

    var sheet = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(today.AddDays(-1), today));
    timesheets.AddLine(sheet.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 60, CostType.Direct, "direct base"));
    timesheets.AddLine(sheet.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 60, CostType.Indirect, "pool cost"));
    timesheets.Submit(new SubmitTimesheetRequest(sheet.Id, "attest"));

    s.TenantContext.UserId = s.Seed.SupervisorUserId;
    s.TenantContext.Roles = new[] { "Supervisor" };
    timesheets.Approve(new ApproveTimesheetRequest(sheet.Id));

    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };
    accounting.PostApprovedTimeCardsToLedger();

    var rateCalcs = indirect.ComputeRates(new ComputeIndirectRatesRequest(sheet.PeriodStart, sheet.PeriodEnd, false));
    Assert(rateCalcs.Count > 0, "Indirect rate computation did not create rate calculations.");
    Assert(rateCalcs.Any(x => x.Rate > 0m), "Indirect rate should be greater than zero for seeded direct/indirect labor.");

    var applied = indirect.ApplyBurden(new ApplyIndirectBurdenRequest(sheet.PeriodStart, sheet.PeriodEnd, null, null, true));
    Assert(applied.Count > 0, "Applied burden entries were not created.");
    Assert(applied.All(x => x.PostedJournalEntryId.HasValue), "Applied burden entries should be posted to GL.");

    var poolId = rateCalcs.First().IndirectPoolId;
    var rerated = indirect.Rerate(new RerateIndirectBurdenRequest(sheet.PeriodStart, sheet.PeriodEnd, poolId, rateCalcs.First().Rate + 0.05m, true, true));
    Assert(rerated.Count > 0, "Rerate should generate delta burden entries.");
    Assert(rerated.Any(x => x.IsAdjustment), "Rerate entries should be marked as adjustments.");
    Assert(rerated.All(x => x.PostedJournalEntryId.HasValue), "Rerated burden entries should be posted to GL.");
}

static void IndirectBaseMethodDirectLaborHoursDrivesRateAndBurden()
{
    var s = CreateScope();
    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var accounting = new AccountingService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var indirect = new IndirectRateService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction, accounting);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);

    var allocationBase = s.Store.AllocationBases.Single(x => x.TenantId == s.Seed.TenantId);
    allocationBase.BaseMethod = AllocationBaseMethod.DirectLaborHours;
    s.Store.SaveChanges();

    var sheet = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(today.AddDays(-1), today));
    var directLine = timesheets.AddLine(sheet.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 120, CostType.Direct, "direct base hours"));
    _ = timesheets.AddLine(sheet.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 60, CostType.Indirect, "pool cost"));
    timesheets.Submit(new SubmitTimesheetRequest(sheet.Id, "attest"));

    s.TenantContext.UserId = s.Seed.SupervisorUserId;
    s.TenantContext.Roles = new[] { "Supervisor" };
    timesheets.Approve(new ApproveTimesheetRequest(sheet.Id));

    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };
    accounting.PostApprovedTimeCardsToLedger();

    var rateCalcs = indirect.ComputeRates(new ComputeIndirectRatesRequest(sheet.PeriodStart, sheet.PeriodEnd, false));
    var calc = rateCalcs.Single();
    Assert(calc.AllocationBaseTotal == 2.00m, "Direct labor hours base should produce 2.00 base hours.");
    Assert(calc.Rate == 27.5m, "Rate should be pool cost divided by direct labor hours.");

    var applied = indirect.ApplyBurden(new ApplyIndirectBurdenRequest(sheet.PeriodStart, sheet.PeriodEnd, calc.IndirectPoolId, calc.Id, false));
    var appliedDirect = applied.Single(x => x.TimesheetLineId == directLine.Id);
    Assert(appliedDirect.BaseAmount == 2.00m, "Applied burden base amount should be tracked in base hours for DirectLaborHours method.");
    Assert(appliedDirect.BurdenAmount == 55.00m, "Applied burden amount should equal base hours multiplied by computed hourly burden rate.");
}

static void FinalIndirectRatesRequireManagerApprovalBeforeApply()
{
    var s = CreateScope();
    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var accounting = new AccountingService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var indirect = new IndirectRateService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction, accounting);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);

    var sheet = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(today.AddDays(-1), today));
    timesheets.AddLine(sheet.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 60, CostType.Direct, "direct base"));
    timesheets.AddLine(sheet.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 30, CostType.Indirect, "pool cost"));
    timesheets.Submit(new SubmitTimesheetRequest(sheet.Id, "attest"));

    s.TenantContext.UserId = s.Seed.SupervisorUserId;
    s.TenantContext.Roles = new[] { "Supervisor" };
    timesheets.Approve(new ApproveTimesheetRequest(sheet.Id));

    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };
    accounting.PostApprovedTimeCardsToLedger();

    var finalCalcs = indirect.ComputeRates(new ComputeIndirectRatesRequest(sheet.PeriodStart, sheet.PeriodEnd, true));
    var finalCalc = finalCalcs.First();
    Assert(finalCalc.ReviewStatus == RateCalculationReviewStatus.PendingManagerApproval, "Final rate should be pending manager approval.");

    ExpectThrows<DomainRuleException>(() => indirect.ApplyBurden(new ApplyIndirectBurdenRequest(sheet.PeriodStart, sheet.PeriodEnd, finalCalc.IndirectPoolId, finalCalc.Id, true)));

    ExpectThrows<DomainRuleException>(() => indirect.ApproveFinalRate(finalCalc.Id, "invalid role"));

    s.TenantContext.UserId = s.Seed.ManagerUserId;
    s.TenantContext.Roles = new[] { "Manager" };
    indirect.ApproveFinalRate(finalCalc.Id, "Manager approved final rate.");

    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };
    var applied = indirect.ApplyBurden(new ApplyIndirectBurdenRequest(sheet.PeriodStart, sheet.PeriodEnd, finalCalc.IndirectPoolId, finalCalc.Id, true));
    Assert(applied.Count > 0, "Approved final rate should apply burden entries.");
}

static void BillingRunApprovalRequiresManagerRole()
{
    var s = CreateScope();
    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var accounting = new AccountingService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var billing = new BillingService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction, s.Notifications);
    var policy = s.Store.ManagementReviewPolicies.Single(x => x.TenantId == s.Seed.TenantId);
    policy.RequireManagerApprovalForBillingAboveThreshold = true;
    policy.BillingManagerApprovalThreshold = 10m;
    s.Store.SaveChanges();
    var today = DateOnly.FromDateTime(DateTime.UtcNow);
    var start = today.AddDays(-1);
    var end = today;

    var t = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(start, end));
    timesheets.AddLine(t.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 60, CostType.Direct, "direct"));
    timesheets.Submit(new SubmitTimesheetRequest(t.Id, "attest"));

    s.TenantContext.UserId = s.Seed.SupervisorUserId;
    s.TenantContext.Roles = new[] { "Supervisor" };
    timesheets.Approve(new ApproveTimesheetRequest(t.Id));

    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };
    accounting.PostApprovedTimeCardsToLedger();

    var run = billing.GenerateBillingRun(new CreateBillingRunRequest(start, end, null, "approval role test"));
    ExpectThrows<DomainRuleException>(() => billing.ApproveBillingRun(new ApproveBillingRunRequest(run.Id, "accountant approve attempt")));
}

static void PeriodCloseRequiresManagerRole()
{
    var s = CreateScope();
    var close = new CloseService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var period = s.Store.AccountingPeriods.First(x => x.TenantId == s.Seed.TenantId);

    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };
    ExpectThrows<DomainRuleException>(() => close.ClosePeriod(period.Id, "attempted accountant close"));
}

static void MonthlyCloseComplianceFlagsOverdueOpenPeriods()
{
    var s = CreateScope();
    var monthlyClose = new MonthlyCloseComplianceService(s.Repository, s.TenantContext, s.Clock);
    var oldStart = DateOnly.FromDateTime(DateTime.UtcNow.Date.AddDays(-90));
    var oldEnd = DateOnly.FromDateTime(DateTime.UtcNow.Date.AddDays(-60));
    s.Store.AccountingPeriods.Add(new AccountingPeriod
    {
        TenantId = s.Seed.TenantId,
        StartDate = oldStart,
        EndDate = oldEnd,
        Status = AccountingPeriodStatus.Open
    });
    s.Store.SaveChanges();

    var rows = monthlyClose.CloseCadenceStatus(DateOnly.FromDateTime(DateTime.UtcNow.Date), 10);
    var overdue = rows.Where(x => x.IsOverdue).ToList();
    Assert(overdue.Count > 0, "Expected at least one overdue open period.");
    Assert(overdue.Any(x => x.StartDate == oldStart && x.EndDate == oldEnd), "Expected seeded old open period to be flagged overdue.");
}

static void InternalAuditCycleRequiresChecklistAndAttestationsBeforeCompletion()
{
    var s = CreateScope();
    var internalAudit = new InternalAuditService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction, s.Notifications);
    var periodStart = DateOnly.FromDateTime(DateTime.UtcNow.Date.AddDays(-75));
    var periodEnd = DateOnly.FromDateTime(DateTime.UtcNow.Date.AddDays(-45));
    var period = new AccountingPeriod
    {
        TenantId = s.Seed.TenantId,
        StartDate = periodStart,
        EndDate = periodEnd,
        Status = AccountingPeriodStatus.Open
    };
    s.Store.AccountingPeriods.Add(period);
    s.Store.SaveChanges();

    var created = internalAudit.SyncCycles(DateOnly.FromDateTime(DateTime.UtcNow.Date));
    Assert(created.Any(x => x.AccountingPeriodId == period.Id), "Internal audit sync should create a cycle for the period.");
    var cycle = s.Store.InternalAuditCycles.Single(x => x.AccountingPeriodId == period.Id);

    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };
    ExpectThrows<DomainRuleException>(() => internalAudit.SubmitForAttestation(new SubmitInternalAuditCycleRequest(cycle.Id, "attempt submit without checklist")));

    internalAudit.UpsertChecklist(new UpsertInternalAuditChecklistRequest(cycle.Id, true, true, true, true, "Checklist complete."));
    internalAudit.SubmitForAttestation(new SubmitInternalAuditCycleRequest(cycle.Id, "Submitted for periodic attestation."));

    s.TenantContext.UserId = s.Seed.ManagerUserId;
    s.TenantContext.Roles = new[] { "Manager" };
    internalAudit.RecordAttestation(new RecordInternalAuditAttestationRequest(cycle.Id, InternalAuditAttestationType.Manager, "Manager attests controls are operating.", null));

    ExpectThrows<DomainRuleException>(() => internalAudit.CompleteCycle(new CompleteInternalAuditCycleRequest(cycle.Id, "cannot complete with missing compliance attestation")));

    s.TenantContext.UserId = s.Seed.ComplianceUserId;
    s.TenantContext.Roles = new[] { "Compliance" };
    internalAudit.RecordAttestation(new RecordInternalAuditAttestationRequest(cycle.Id, InternalAuditAttestationType.Compliance, "Compliance attests periodic review performed.", null));

    s.TenantContext.UserId = s.Seed.ManagerUserId;
    s.TenantContext.Roles = new[] { "Manager" };
    var completed = internalAudit.CompleteCycle(new CompleteInternalAuditCycleRequest(cycle.Id, "Completed after all attestations."));
    Assert(completed.Status == InternalAuditCycleStatus.Completed, "Internal audit cycle should be completed.");
}

static void InternalAuditComplianceReportFlagsOverdueIncompleteCycles()
{
    var s = CreateScope();
    var internalAudit = new InternalAuditService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction, s.Notifications);
    var policy = s.Store.ManagementReviewPolicies.Single(x => x.TenantId == s.Seed.TenantId);
    policy.InternalAuditDueDaysAfterPeriodEnd = 5;
    s.Store.SaveChanges();

    var periodStart = DateOnly.FromDateTime(DateTime.UtcNow.Date.AddDays(-90));
    var periodEnd = DateOnly.FromDateTime(DateTime.UtcNow.Date.AddDays(-60));
    var period = new AccountingPeriod
    {
        TenantId = s.Seed.TenantId,
        StartDate = periodStart,
        EndDate = periodEnd,
        Status = AccountingPeriodStatus.Open
    };
    s.Store.AccountingPeriods.Add(period);
    s.Store.SaveChanges();

    internalAudit.SyncCycles(DateOnly.FromDateTime(DateTime.UtcNow.Date));
    var rows = internalAudit.ComplianceReport(DateOnly.FromDateTime(DateTime.UtcNow.Date));
    var overdue = rows.SingleOrDefault(x => x.PeriodStart == periodStart && x.PeriodEnd == periodEnd);
    if (overdue is null)
    {
        throw new InvalidOperationException("Internal audit compliance row should exist for the seeded period.");
    }
    Assert(overdue.IsOverdue, "Expected incomplete old internal audit cycle to be overdue.");
    Assert(overdue.RequiredAttestations >= 1, "Expected at least one required attestation.");
}

static void ComplianceReviewRequiresAttestationBeforeSubmit()
{
    var s = CreateScope();
    var internalAudit = new InternalAuditService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction, s.Notifications);
    var cycle = CreateReviewCycleForInternalAuditTests(s, internalAudit);
    SetAllChecklistItems(internalAudit, cycle.Id, ComplianceChecklistResult.Pass, null);

    internalAudit.SubmitForAttestation(new SubmitInternalAuditCycleRequest(cycle.Id, "Ready for attestations."));
    ExpectThrows<DomainRuleException>(() => internalAudit.SubmitReview(new SubmitInternalAuditCycleRequest(cycle.Id, "Attempt submit without attestation.")));

    s.TenantContext.UserId = s.Seed.ManagerUserId;
    s.TenantContext.Roles = new[] { "Manager" };
    internalAudit.RecordAttestation(new RecordInternalAuditAttestationRequest(cycle.Id, InternalAuditAttestationType.Manager, "Manager attests control review.", null));

    var submitted = internalAudit.SubmitReview(new SubmitInternalAuditCycleRequest(cycle.Id, "Submitted after attestation."));
    Assert(submitted.Status == InternalAuditCycleStatus.Submitted, "Review should move to submitted after attestation.");
}

static void ApproverCannotBeSubmitterMakerCheckerEnforced()
{
    var s = CreateScope();
    var internalAudit = new InternalAuditService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction, s.Notifications);
    var cycle = CreateReviewCycleForInternalAuditTests(s, internalAudit);
    SetAllChecklistItems(internalAudit, cycle.Id, ComplianceChecklistResult.Pass, null);

    s.TenantContext.UserId = s.Seed.ManagerUserId;
    s.TenantContext.Roles = new[] { "Manager" };
    internalAudit.SubmitForAttestation(new SubmitInternalAuditCycleRequest(cycle.Id, "Manager submitted for attestation."));
    internalAudit.RecordAttestation(new RecordInternalAuditAttestationRequest(cycle.Id, InternalAuditAttestationType.Manager, "Manager attestation.", null));
    internalAudit.SubmitReview(new SubmitInternalAuditCycleRequest(cycle.Id, "Manager submitted review."));

    ExpectThrows<DomainRuleException>(() => internalAudit.ApproveReview(new ApproveInternalAuditCycleRequest(cycle.Id, "Self-approval must fail.")));
}

static void FailedChecklistItemGeneratesException()
{
    var s = CreateScope();
    var internalAudit = new InternalAuditService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction, s.Notifications);
    var cycle = CreateReviewCycleForInternalAuditTests(s, internalAudit);
    var checklistItems = internalAudit.AutoPopulateChecklistFromClauseMatrix(new AutoPopulateInternalAuditChecklistRequest(cycle.Id));
    var failItem = checklistItems.First(x => x.ClauseRef == "(c)(11)");
    internalAudit.UpsertChecklistItem(new UpsertInternalAuditChecklistItemRequest(cycle.Id, failItem.Id, ComplianceChecklistResult.Fail, "Monthly close evidence missing."));

    var exceptions = internalAudit.Exceptions(cycle.Id);
    Assert(exceptions.Any(x => x.ChecklistItemId == failItem.Id && x.Status == ComplianceExceptionStatus.Open.ToString()), "Failed checklist item should create an open exception.");
}

static void ReviewCannotCloseWithOpenExceptionsUnlessAcceptedRiskByManager()
{
    var s = CreateScope();
    var internalAudit = new InternalAuditService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction, s.Notifications);
    var cycle = CreateReviewCycleForInternalAuditTests(s, internalAudit);
    SetAllChecklistItems(internalAudit, cycle.Id, ComplianceChecklistResult.Pass, "(baseline)");
    var closeChecklist = internalAudit.Checklist(cycle.Id).Single(x => x.ClauseRef == "(c)(11)");
    internalAudit.UpsertChecklistItem(new UpsertInternalAuditChecklistItemRequest(cycle.Id, closeChecklist.ChecklistItemId, ComplianceChecklistResult.Fail, "Overdue close detected."));

    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };
    internalAudit.SubmitForAttestation(new SubmitInternalAuditCycleRequest(cycle.Id, "Submitted to collect attestations."));

    s.TenantContext.UserId = s.Seed.ComplianceUserId;
    s.TenantContext.Roles = new[] { "Compliance" };
    internalAudit.RecordAttestation(new RecordInternalAuditAttestationRequest(cycle.Id, InternalAuditAttestationType.Compliance, "Compliance attests.", null));
    internalAudit.SubmitReview(new SubmitInternalAuditCycleRequest(cycle.Id, "Submitted for manager approval."));

    s.TenantContext.UserId = s.Seed.ManagerUserId;
    s.TenantContext.Roles = new[] { "Manager" };
    internalAudit.ApproveReview(new ApproveInternalAuditCycleRequest(cycle.Id, "Approved for closure review."));

    ExpectThrows<DomainRuleException>(() => internalAudit.CloseReview(new CompleteInternalAuditCycleRequest(cycle.Id, "Should fail with open exceptions.")));

    var openException = internalAudit.Exceptions(cycle.Id).Single(x => x.Status == ComplianceExceptionStatus.Open.ToString());
    internalAudit.AcceptRisk(new AcceptComplianceRiskRequest(openException.ComplianceExceptionId, "Manager accepted risk for documented condition."));
    var closed = internalAudit.CloseReview(new CompleteInternalAuditCycleRequest(cycle.Id, "Closed with accepted risk."));
    Assert(closed.Status == InternalAuditCycleStatus.Closed, "Review should close after manager accepts risk.");
}

static void BillingThresholdRoutesApprovalToManagerForHighValueRuns()
{
    var s = CreateScope();
    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var accounting = new AccountingService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var billing = new BillingService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction, s.Notifications);
    var policy = s.Store.ManagementReviewPolicies.Single(x => x.TenantId == s.Seed.TenantId);
    policy.RequireManagerApprovalForBillingAboveThreshold = true;
    policy.BillingManagerApprovalThreshold = 10m;
    s.Store.SaveChanges();

    var today = DateOnly.FromDateTime(DateTime.UtcNow);
    var start = today.AddDays(-1);
    var end = today;
    var t = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(start, end));
    timesheets.AddLine(t.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 60, CostType.Direct, "direct"));
    timesheets.Submit(new SubmitTimesheetRequest(t.Id, "attest"));

    s.TenantContext.UserId = s.Seed.SupervisorUserId;
    s.TenantContext.Roles = new[] { "Supervisor" };
    timesheets.Approve(new ApproveTimesheetRequest(t.Id));

    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };
    accounting.PostApprovedTimeCardsToLedger();

    var run = billing.GenerateBillingRun(new CreateBillingRunRequest(start, end, null, "threshold routing"));
    ExpectThrows<DomainRuleException>(() => billing.ApproveBillingRun(new ApproveBillingRunRequest(run.Id, "accountant blocked above threshold")));

    s.TenantContext.UserId = s.Seed.ManagerUserId;
    s.TenantContext.Roles = new[] { "Manager" };
    billing.ApproveBillingRun(new ApproveBillingRunRequest(run.Id, "manager approval above threshold"));
}

static void AdjustingThresholdRequiresManagerCoSignOnlyForHighValueEntries()
{
    var s = CreateScope();
    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };
    var accounting = new AccountingService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    accounting.PostApprovedTimeCardsToLedger();
    var workflow = new JournalEntryWorkflowService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction, s.Notifications);
    var policy = s.Store.ManagementReviewPolicies.Single(x => x.TenantId == s.Seed.TenantId);
    var account5000 = s.Store.ChartOfAccounts.Single(x => x.AccountNumber == "5000");
    var account2100 = s.Store.ChartOfAccounts.Single(x => x.AccountNumber == "2100");

    var reviewer = new AppUser
    {
        TenantId = s.Seed.TenantId,
        UserName = "accounting_reviewer",
        Email = "accounting_reviewer@example.com"
    };
    reviewer.Roles.Add("Accountant");
    s.Store.Users.Add(reviewer);
    s.Store.SaveChanges();

    policy.RequireManagerCoSignForAdjustingAboveThreshold = true;
    policy.AdjustingManagerCoSignThreshold = 50m;
    s.Store.SaveChanges();

    var high = workflow.CreateAdjustingEntry(new CreateAdjustingJournalEntryRequest(
        DateOnly.FromDateTime(DateTime.UtcNow),
        "High value adjusting",
        "threshold test high",
        null,
        [
            new AdjustingJournalLineRequest(account5000.Id, 100m, 0m),
            new AdjustingJournalLineRequest(account2100.Id, 0m, 100m)
        ]));
    workflow.SubmitAdjustingEntry(new SubmitAdjustingJournalEntryRequest(high.Id, "submit high"));

    s.TenantContext.UserId = reviewer.Id;
    s.TenantContext.Roles = new[] { "Accountant" };
    ExpectThrows<DomainRuleException>(() => workflow.ApproveAdjustingEntry(new ApproveAdjustingJournalEntryRequest(high.Id, "blocked high", null)));

    s.TenantContext.UserId = s.Seed.ManagerUserId;
    s.TenantContext.Roles = new[] { "Manager" };
    workflow.ApproveAdjustingEntry(new ApproveAdjustingJournalEntryRequest(high.Id, "manager approves high", null));

    policy.AdjustingManagerCoSignThreshold = 1000m;
    s.Store.SaveChanges();

    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };
    var low = workflow.CreateAdjustingEntry(new CreateAdjustingJournalEntryRequest(
        DateOnly.FromDateTime(DateTime.UtcNow),
        "Low value adjusting",
        "threshold test low",
        null,
        [
            new AdjustingJournalLineRequest(account5000.Id, 100m, 0m),
            new AdjustingJournalLineRequest(account2100.Id, 0m, 100m)
        ]));
    workflow.SubmitAdjustingEntry(new SubmitAdjustingJournalEntryRequest(low.Id, "submit low"));

    s.TenantContext.UserId = reviewer.Id;
    s.TenantContext.Roles = new[] { "Accountant" };
    workflow.ApproveAdjustingEntry(new ApproveAdjustingJournalEntryRequest(low.Id, "accountant approves low", null));
}

static void SubledgerToGlReconciliationDetectsVariance()
{
    var s = CreateScope();
    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var accounting = new AccountingService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var close = new CloseService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);

    var sheet = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(today.AddDays(-1), today));
    timesheets.AddLine(sheet.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 60, CostType.Direct, "work"));
    timesheets.Submit(new SubmitTimesheetRequest(sheet.Id, "attest"));
    s.TenantContext.UserId = s.Seed.SupervisorUserId;
    s.TenantContext.Roles = new[] { "Supervisor" };
    timesheets.Approve(new ApproveTimesheetRequest(sheet.Id));
    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };
    accounting.PostApprovedTimeCardsToLedger();

    var initial = close.SubledgerToGlReconciliation(sheet.PeriodStart, sheet.PeriodEnd);
    Assert(initial.Any(x => x.Area == "Labor" && x.Status == "Matched"), "Labor tie-out should initially match.");

    var account5000 = s.Store.ChartOfAccounts.Single(x => x.AccountNumber == "5000");
    var extraJe = new JournalEntry
    {
        TenantId = s.Seed.TenantId,
        EntryDate = sheet.PeriodEnd,
        Description = "Forced mismatch",
        IsReversal = false
    };
    s.Repository.Add(extraJe);
    s.Repository.Add(new JournalLine
    {
        TenantId = s.Seed.TenantId,
        JournalEntryId = extraJe.Id,
        AccountId = account5000.Id,
        Debit = 10m,
        Credit = 0m
    });

    var mismatch = close.SubledgerToGlReconciliation(sheet.PeriodStart, sheet.PeriodEnd);
    Assert(mismatch.Any(x => x.Area == "Labor" && x.Status == "Variance"), "Labor tie-out should flag variance when GL diverges from subledger.");
}

static void AdjustingJeMakerCheckerEnforced()
{
    var s = CreateScope();
    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };
    var accounting = new AccountingService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    accounting.PostApprovedTimeCardsToLedger();
    var workflow = new JournalEntryWorkflowService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction, s.Notifications);

    var account5000 = s.Store.ChartOfAccounts.Single(x => x.AccountNumber == "5000");
    var account2100 = s.Store.ChartOfAccounts.Single(x => x.AccountNumber == "2100");
    var entry = workflow.CreateAdjustingEntry(new CreateAdjustingJournalEntryRequest(
        DateOnly.FromDateTime(DateTime.UtcNow),
        "Accrual adjustment",
        "Month end adjusting entry",
        null,
        [
            new AdjustingJournalLineRequest(account5000.Id, 100m, 0m),
            new AdjustingJournalLineRequest(account2100.Id, 0m, 100m)
        ]));
    workflow.SubmitAdjustingEntry(new SubmitAdjustingJournalEntryRequest(entry.Id, "submit"));

    s.TenantContext.Roles = new[] { "Accountant", "Manager" };
    ExpectThrows<DomainRuleException>(() => workflow.ApproveAdjustingEntry(new ApproveAdjustingJournalEntryRequest(entry.Id, "self approve", null)));

    s.TenantContext.UserId = s.Seed.ManagerUserId;
    s.TenantContext.Roles = new[] { "Manager" };
    workflow.ApproveAdjustingEntry(new ApproveAdjustingJournalEntryRequest(entry.Id, "approved by separate accountant", null));

    var reloaded = s.Store.JournalEntries.Single(x => x.Id == entry.Id);
    Assert(reloaded.Status == JournalEntryStatus.Approved, "Entry should be approved by manager.");
}

static void PostedAdjustingJeImmutableExceptReversal()
{
    var s = CreateScope();
    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };
    var accounting = new AccountingService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    accounting.PostApprovedTimeCardsToLedger();
    var workflow = new JournalEntryWorkflowService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction, s.Notifications);

    var account5000 = s.Store.ChartOfAccounts.Single(x => x.AccountNumber == "5000");
    var account2100 = s.Store.ChartOfAccounts.Single(x => x.AccountNumber == "2100");
    var entry = workflow.CreateAdjustingEntry(new CreateAdjustingJournalEntryRequest(
        DateOnly.FromDateTime(DateTime.UtcNow),
        "Accrual adjustment",
        "Month end adjusting entry",
        null,
        [
            new AdjustingJournalLineRequest(account5000.Id, 100m, 0m),
            new AdjustingJournalLineRequest(account2100.Id, 0m, 100m)
        ]));
    workflow.SubmitAdjustingEntry(new SubmitAdjustingJournalEntryRequest(entry.Id, "submit"));

    s.TenantContext.UserId = s.Seed.ManagerUserId;
    s.TenantContext.Roles = new[] { "Manager" };
    workflow.ApproveAdjustingEntry(new ApproveAdjustingJournalEntryRequest(entry.Id, "approved", null));
    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };
    workflow.PostApprovedEntry(new PostAdjustingJournalEntryRequest(entry.Id, "post"));

    ExpectThrows<DomainRuleException>(() => workflow.SubmitAdjustingEntry(new SubmitAdjustingJournalEntryRequest(entry.Id, "resubmit attempt")));
    ExpectThrows<DomainRuleException>(() => workflow.ApproveAdjustingEntry(new ApproveAdjustingJournalEntryRequest(entry.Id, "reapprove attempt", null)));

    var reversal = workflow.ReverseEntry(new ReverseJournalEntryRequest(entry.Id, null, "reverse"));
    Assert(reversal.ReversalOfJournalEntryId == entry.Id, "Reversal should link to original entry.");
}

static void AdjustingJeReversalLinksAndBalances()
{
    var s = CreateScope();
    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };
    var accounting = new AccountingService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    accounting.PostApprovedTimeCardsToLedger();
    var workflow = new JournalEntryWorkflowService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction, s.Notifications);

    var account5000 = s.Store.ChartOfAccounts.Single(x => x.AccountNumber == "5000");
    var account2100 = s.Store.ChartOfAccounts.Single(x => x.AccountNumber == "2100");
    var entry = workflow.CreateAdjustingEntry(new CreateAdjustingJournalEntryRequest(
        DateOnly.FromDateTime(DateTime.UtcNow),
        "Payroll true-up",
        "Accrual correction",
        null,
        [
            new AdjustingJournalLineRequest(account5000.Id, 80m, 0m),
            new AdjustingJournalLineRequest(account2100.Id, 0m, 80m)
        ]));
    workflow.SubmitAdjustingEntry(new SubmitAdjustingJournalEntryRequest(entry.Id, "submit"));

    s.TenantContext.UserId = s.Seed.ManagerUserId;
    s.TenantContext.Roles = new[] { "Manager" };
    workflow.ApproveAdjustingEntry(new ApproveAdjustingJournalEntryRequest(entry.Id, "approved", null));
    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };
    workflow.PostApprovedEntry(new PostAdjustingJournalEntryRequest(entry.Id, "post"));

    var reversal = workflow.ReverseEntry(new ReverseJournalEntryRequest(entry.Id, DateOnly.FromDateTime(DateTime.UtcNow), "reverse"));
    var reversalLines = s.Store.JournalLines.Where(x => x.JournalEntryId == reversal.Id).ToList();
    Assert(reversalLines.Count == 2, "Reversal should mirror two journal lines.");
    Assert(Math.Round(reversalLines.Sum(x => x.Debit), 2) == Math.Round(reversalLines.Sum(x => x.Credit), 2), "Reversal entry must be balanced.");
    Assert(s.Store.JournalEntries.Single(x => x.Id == entry.Id).Status == JournalEntryStatus.Reversed, "Original entry should be marked reversed.");
}

static void BillingGenerationExcludesUnallowables()
{
    var s = CreateScope();
    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var accounting = new AccountingService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var billing = new BillingService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction, s.Notifications);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);
    var start = today.AddDays(-1);
    var end = today;

    var t = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(start, end));
    timesheets.AddLine(t.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 60, CostType.Direct, "direct"));
    timesheets.AddLine(t.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 60, CostType.Unallowable, "unallowable labor"));
    var allowableExpense = timesheets.AddExpense(t.Id, new AddTimesheetExpenseRequest(today, s.Seed.ChargeCodeId, 100m, CostType.Direct, "Travel", "allowable"));
    var unallowableExpense = timesheets.AddExpense(t.Id, new AddTimesheetExpenseRequest(today, s.Seed.ChargeCodeId, 50m, CostType.Direct, "Meals", "unallowable"));
    timesheets.Submit(new SubmitTimesheetRequest(t.Id, "attest"));

    s.TenantContext.UserId = s.Seed.SupervisorUserId;
    s.TenantContext.Roles = new[] { "Supervisor" };
    timesheets.ApproveExpense(t.Id, allowableExpense.Id);
    timesheets.ApproveExpense(t.Id, unallowableExpense.Id);
    timesheets.Approve(new ApproveTimesheetRequest(t.Id));

    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };
    timesheets.AssignExpenseAccountingCategory(unallowableExpense.Id, ExpenseAccountingCategory.Unallowable, "exclude from billings");
    accounting.PostApprovedTimeCardsToLedger();

    billing.GenerateBillingRun(new CreateBillingRunRequest(start, end, null, "test"));
    var invoiceLines = s.Store.InvoiceLines.ToList();
    Assert(invoiceLines.Count > 0, "Billing run should generate invoice lines.");
    Assert(invoiceLines.All(x => x.CostType != CostType.Unallowable), "Unallowable labor should be excluded from billing lines.");
    var hasUnallowableExpenseLink = s.Store.BilledCostLinks
        .Join(s.Store.InvoiceLines, l => l.InvoiceLineId, il => il.Id, (l, il) => new { l, il })
        .Any(x => x.l.SourceEntityId == unallowableExpense.Id);
    Assert(!hasUnallowableExpenseLink, "Unallowable expense should not be linked to billed costs.");
}

static void BillingCeilingEnforcementBlocksOverbilling()
{
    var s = CreateScope();
    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var accounting = new AccountingService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var billing = new BillingService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction, s.Notifications);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);
    var start = today.AddDays(-1);
    var end = today;

    var t = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(start, end));
    timesheets.AddLine(t.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 60, CostType.Direct, "direct"));
    timesheets.Submit(new SubmitTimesheetRequest(t.Id, "attest"));

    s.TenantContext.UserId = s.Seed.SupervisorUserId;
    s.TenantContext.Roles = new[] { "Supervisor" };
    timesheets.Approve(new ApproveTimesheetRequest(t.Id));

    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };
    accounting.PostApprovedTimeCardsToLedger();

    var contract = s.Store.Contracts.Single();
    billing.UpsertCeiling(new UpsertBillingCeilingRequest(contract.Id, 20m, 20m, start, end, true));
    ExpectThrows<DomainRuleException>(() => billing.GenerateBillingRun(new CreateBillingRunRequest(start, end, contract.Id, "ceiling test")));
}

static void BilledToBookedReconciliationTiesToGl()
{
    var s = CreateScope();
    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var accounting = new AccountingService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var billing = new BillingService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction, s.Notifications);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);
    var start = today.AddDays(-1);
    var end = today;

    var t = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(start, end));
    timesheets.AddLine(t.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 60, CostType.Direct, "direct"));
    timesheets.Submit(new SubmitTimesheetRequest(t.Id, "attest"));

    s.TenantContext.UserId = s.Seed.SupervisorUserId;
    s.TenantContext.Roles = new[] { "Supervisor" };
    timesheets.Approve(new ApproveTimesheetRequest(t.Id));

    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };
    accounting.PostApprovedTimeCardsToLedger();

    var run = billing.GenerateBillingRun(new CreateBillingRunRequest(start, end, null, "recon"));
    s.TenantContext.UserId = s.Seed.ManagerUserId;
    s.TenantContext.Roles = new[] { "Manager" };
    billing.ApproveBillingRun(new ApproveBillingRunRequest(run.Id, "approve"));
    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };
    billing.PostBillingRun(new PostBillingRunRequest(run.Id, "post"));

    var reconciliation = billing.BilledToBookedReconciliation(start, end, null);
    Assert(reconciliation.Count > 0, "Billing reconciliation should return rows.");
    Assert(reconciliation.All(x => x.Status == "Matched"), "Billed-to-booked reconciliation should match for seeded scenario.");
}

static void ClinTrackedContractBlocksUnmappedChargeCodes()
{
    var s = CreateScope();
    var compliance = new ComplianceService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);

    var contract = compliance.CreateContract("CLIN-REQ-1", "CLIN Required", 100000m, ContractType.CostPlusFee, today.AddDays(-30), today.AddDays(365), true);
    var taskOrder = compliance.CreateTaskOrder(contract.Id, "TO-CLIN", 50000m, true);
    var clin = compliance.CreateClin(taskOrder.Id, "0001AA");
    var wbs = compliance.CreateWbs(clin.Id, "1.1", null);
    _ = compliance.CreateChargeCode(wbs.Id, "CC-VALID-CLIN", CostType.Direct);

    var invalidChargeCode = new ChargeCode
    {
        TenantId = s.Seed.TenantId,
        WbsNodeId = Guid.NewGuid(),
        Code = "CC-BROKEN-CLIN",
        CostType = CostType.Direct,
        IsActive = true
    };
    s.Store.ChargeCodes.Add(invalidChargeCode);
    s.Store.Assignments.Add(new Assignment
    {
        TenantId = s.Seed.TenantId,
        UserId = s.Seed.TimeReporterUserId,
        ChargeCodeId = invalidChargeCode.Id,
        EffectiveStartDate = today.AddDays(-10),
        EffectiveEndDate = today.AddDays(10),
        SupervisorOverrideAllowed = false
    });
    s.Store.SaveChanges();

    var t = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(today.AddDays(-1), today));
    timesheets.AddLine(t.Id, new AddTimesheetLineRequest(today, invalidChargeCode.Id, 60, CostType.Direct, "broken chain"));
    ExpectThrows<DomainRuleException>(() => timesheets.Submit(new SubmitTimesheetRequest(t.Id, "attest")));
}

static void ClinSummaryRollupTiesToPostedLabor()
{
    var s = CreateScope();
    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var accounting = new AccountingService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var reporting = new ReportingService(s.Repository, s.TenantContext);
    var today = DateOnly.FromDateTime(DateTime.UtcNow);
    var start = today.AddDays(-1);
    var end = today;

    var t = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(start, end));
    timesheets.AddLine(t.Id, new AddTimesheetLineRequest(today, s.Seed.ChargeCodeId, 120, CostType.Direct, "clin rollup"));
    timesheets.Submit(new SubmitTimesheetRequest(t.Id, "attest"));

    s.TenantContext.UserId = s.Seed.SupervisorUserId;
    s.TenantContext.Roles = new[] { "Supervisor" };
    timesheets.Approve(new ApproveTimesheetRequest(t.Id));

    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };
    accounting.PostApprovedTimeCardsToLedger();

    var rows = reporting.ClinSummary(start, end, null);
    Assert(rows.Count > 0, "CLIN summary should contain rollup rows.");

    var laborFromClinSummary = Math.Round(rows.Sum(x => x.LaborDollars), 2);
    var account5000 = s.Store.ChartOfAccounts.Single(x => x.AccountNumber == "5000");
    var entryIds = s.Store.JournalEntries.Where(x => x.EntryDate >= start && x.EntryDate <= end).Select(x => x.Id).ToHashSet();
    var laborFromGl = Math.Round(s.Store.JournalLines.Where(x => entryIds.Contains(x.JournalEntryId) && x.AccountId == account5000.Id).Sum(x => x.Debit - x.Credit), 2);
    Assert(laborFromClinSummary == laborFromGl, "CLIN summary labor dollars should tie to posted GL labor for direct labor account.");
    Assert(rows.All(x => !string.IsNullOrWhiteSpace(x.ClinNumber) && !string.IsNullOrWhiteSpace(x.TaskOrderNumber)), "CLIN summary rows should include task order and CLIN identifiers.");
}

static void GenerateAuditBinderEvidencePackage()
{
    var s = CreateScope();
    var today = DateOnly.FromDateTime(DateTime.UtcNow);
    var periodStart = today.AddDays(-1);
    var periodEnd = today;

    var config = s.Store.WorkPeriodConfigurations.Single(x => x.TenantId == s.Seed.TenantId);
    config.DailyEntryGraceDays = 14;
    s.Store.SaveChanges();

    var timesheets = new TimesheetService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var accounting = new AccountingService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var indirect = new IndirectRateService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction, accounting);
    var billing = new BillingService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction, s.Notifications);
    var close = new CloseService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction);
    var monthlyClose = new MonthlyCloseComplianceService(s.Repository, s.TenantContext, s.Clock);
    var internalAudit = new InternalAuditService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction, s.Notifications);
    var workflow = new JournalEntryWorkflowService(s.Repository, s.TenantContext, s.Audit, s.Correlation, s.Clock, s.Transaction, s.Notifications);
    var reporting = new ReportingService(s.Repository, s.TenantContext);

    var sheet = timesheets.CreateTimesheetDraft(new CreateTimesheetRequest(periodStart, periodEnd));
    timesheets.AddLine(sheet.Id, new AddTimesheetLineRequest(periodStart, s.Seed.ChargeCodeId, 480, CostType.Direct, "Implementation work"));
    var exp1 = timesheets.AddExpense(sheet.Id, new AddTimesheetExpenseRequest(periodEnd, s.Seed.ChargeCodeId, 120m, CostType.Direct, "Travel", "Mileage"));
    var exp2 = timesheets.AddExpense(sheet.Id, new AddTimesheetExpenseRequest(periodEnd, s.Seed.ChargeCodeId, 45m, CostType.Unallowable, "Meals", "Client dinner"));
    timesheets.Submit(new SubmitTimesheetRequest(sheet.Id, "I attest"));

    s.TenantContext.UserId = s.Seed.SupervisorUserId;
    s.TenantContext.Roles = new[] { "Supervisor" };
    timesheets.ApproveExpense(sheet.Id, exp1.Id);
    timesheets.ApproveExpense(sheet.Id, exp2.Id);
    timesheets.Approve(new ApproveTimesheetRequest(sheet.Id));
    var correction = timesheets.RequestCorrection(new RequestCorrectionRequest(sheet.Id, "Correct labor allocation"));

    s.TenantContext.UserId = s.Seed.TimeReporterUserId;
    s.TenantContext.Roles = new[] { "TimeReporter" };
    var corrected = timesheets.ApplyCorrection(new ApplyCorrectionRequest(
        sheet.Id,
        correction.Id,
        [
            new AddTimesheetLineRequest(periodStart, s.Seed.ChargeCodeId, 420, CostType.Direct, "Corrected implementation"),
            new AddTimesheetLineRequest(periodEnd, s.Seed.ChargeCodeId, 60, CostType.Direct, "Corrected close-out"),
            new AddTimesheetLineRequest(periodEnd, s.Seed.ChargeCodeId, 30, CostType.Indirect, "Indirect support time")
        ],
        "Correct labor allocation"));
    timesheets.Submit(new SubmitTimesheetRequest(corrected.Id, "I attest"));

    s.TenantContext.UserId = s.Seed.SupervisorUserId;
    s.TenantContext.Roles = new[] { "Supervisor" };
    timesheets.Approve(new ApproveTimesheetRequest(corrected.Id));

    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };
    accounting.PostApprovedTimeCardsToLedger();
    var rateCalcs = indirect.ComputeRates(new ComputeIndirectRatesRequest(periodStart, periodEnd, false));
    indirect.ApplyBurden(new ApplyIndirectBurdenRequest(periodStart, periodEnd, null, rateCalcs.First().Id, true));

    var run = billing.GenerateBillingRun(new CreateBillingRunRequest(periodStart, periodEnd, null, "Auditor binder run"));
    s.TenantContext.UserId = s.Seed.ManagerUserId;
    s.TenantContext.Roles = new[] { "Manager" };
    billing.ApproveBillingRun(new ApproveBillingRunRequest(run.Id, "Approved for billing evidence"));
    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };
    billing.PostBillingRun(new PostBillingRunRequest(run.Id, "Posted for evidence"));

    var account5000 = s.Store.ChartOfAccounts.Single(x => x.AccountNumber == "5000");
    var account2100 = s.Store.ChartOfAccounts.Single(x => x.AccountNumber == "2100");
    var adjusting = workflow.CreateAdjustingEntry(new CreateAdjustingJournalEntryRequest(
        periodEnd,
        "Accrual true-up",
        "Month-end accrual adjustment",
        "workpaper://JE-ADJ-001",
        [
            new AdjustingJournalLineRequest(account5000.Id, 25m, 0m),
            new AdjustingJournalLineRequest(account2100.Id, 0m, 25m)
        ]));
    workflow.SubmitAdjustingEntry(new SubmitAdjustingJournalEntryRequest(adjusting.Id, "Submitted with support"));

    s.TenantContext.UserId = s.Seed.ManagerUserId;
    s.TenantContext.Roles = new[] { "Manager" };
    workflow.ApproveAdjustingEntry(new ApproveAdjustingJournalEntryRequest(adjusting.Id, "Approved by separate accountant", "workpaper://JE-ADJ-001"));
    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };
    workflow.PostApprovedEntry(new PostAdjustingJournalEntryRequest(adjusting.Id, "Posted to ledger"));
    workflow.ReverseEntry(new ReverseJournalEntryRequest(adjusting.Id, periodEnd, "Demonstrate reversal linkage"));

    var currentPeriod = new AccountingPeriod
    {
        TenantId = s.Seed.TenantId,
        StartDate = periodStart,
        EndDate = periodEnd,
        Status = AccountingPeriodStatus.Open
    };
    s.Store.AccountingPeriods.Add(currentPeriod);
    s.Store.PayrollBatches.Add(new PayrollBatch
    {
        TenantId = s.Seed.TenantId,
        ExternalBatchId = $"BINDER-{DateTime.UtcNow:yyyyMMddHHmmss}",
        SourceSystem = "BinderSeed",
        PeriodStart = periodStart,
        PeriodEnd = periodEnd,
        ImportedByUserId = s.Seed.AccountantUserId,
        SourceChecksum = "binder-seeded"
    });
    s.Store.SaveChanges();

    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };
    ExpectThrows<DomainRuleException>(() => close.ClosePeriod(currentPeriod.Id, "Unauthorized close attempt for audit evidence"));
    s.TenantContext.UserId = s.Seed.ManagerUserId;
    s.TenantContext.Roles = new[] { "Manager" };
    close.ClosePeriod(currentPeriod.Id, "Manager close for binder evidence");

    var priorPeriod = new AccountingPeriod
    {
        TenantId = s.Seed.TenantId,
        StartDate = periodStart.AddDays(-30),
        EndDate = periodStart.AddDays(-1),
        Status = AccountingPeriodStatus.Closed
    };
    s.Store.AccountingPeriods.Add(priorPeriod);
    s.Store.SaveChanges();
    internalAudit.SyncCycles(periodEnd);
    var cycle = s.Store.InternalAuditCycles.Single(x => x.AccountingPeriodId == priorPeriod.Id);
    internalAudit.UpsertChecklist(new UpsertInternalAuditChecklistRequest(cycle.Id, true, true, true, true, "Binder scenario checklist complete."));
    internalAudit.SubmitForAttestation(new SubmitInternalAuditCycleRequest(cycle.Id, "Periodic internal audit submitted."));
    s.TenantContext.UserId = s.Seed.ManagerUserId;
    s.TenantContext.Roles = new[] { "Manager" };
    internalAudit.RecordAttestation(new RecordInternalAuditAttestationRequest(cycle.Id, InternalAuditAttestationType.Manager, "Manager attestation for binder evidence.", null));
    s.TenantContext.UserId = s.Seed.ComplianceUserId;
    s.TenantContext.Roles = new[] { "Compliance" };
    internalAudit.RecordAttestation(new RecordInternalAuditAttestationRequest(cycle.Id, InternalAuditAttestationType.Compliance, "Compliance attestation for binder evidence.", null));
    s.TenantContext.UserId = s.Seed.ManagerUserId;
    s.TenantContext.Roles = new[] { "Manager" };
    internalAudit.CompleteCycle(new CompleteInternalAuditCycleRequest(cycle.Id, "Internal audit cycle completed for binder."));

    var binderPath = GenerateAuditBinder(
        s,
        periodStart,
        periodEnd,
        s.Store.Contracts.First().Id,
        reporting,
        close,
        billing,
        indirect,
        monthlyClose,
        internalAudit);

    Assert(Directory.Exists(binderPath), "Audit binder directory was not created.");
    var files = Directory.GetFiles(binderPath, "*.*", SearchOption.TopDirectoryOnly);
    Assert(files.Length >= 20, "Audit binder should include expected evidence artifacts.");
    Assert(files.Any(x => Path.GetFileName(x).Equals("monthly_close_compliance.csv", StringComparison.OrdinalIgnoreCase)), "Audit binder should include monthly close compliance CSV.");
    Assert(files.Any(x => Path.GetFileName(x).Equals("monthly_close_compliance.json", StringComparison.OrdinalIgnoreCase)), "Audit binder should include monthly close compliance JSON.");
    Assert(files.Any(x => Path.GetFileName(x).Equals("internal_audit_compliance.csv", StringComparison.OrdinalIgnoreCase)), "Audit binder should include internal audit compliance CSV.");
    Assert(files.Any(x => Path.GetFileName(x).Equals("internal_audit_compliance.json", StringComparison.OrdinalIgnoreCase)), "Audit binder should include internal audit compliance JSON.");
    Assert(files.Any(x => Path.GetFileName(x).Equals("internal_audit_cycles.csv", StringComparison.OrdinalIgnoreCase)), "Audit binder should include internal audit cycles CSV.");
    Assert(files.Any(x => Path.GetFileName(x).Equals("internal_audit_attestations.csv", StringComparison.OrdinalIgnoreCase)), "Audit binder should include internal audit attestations CSV.");
    Assert(files.Any(x => Path.GetFileName(x).Equals("compliance_review_summary.csv", StringComparison.OrdinalIgnoreCase)), "Audit binder should include compliance review summary CSV.");
    Assert(files.Any(x => Path.GetFileName(x).Equals("compliance_review_checklist.csv", StringComparison.OrdinalIgnoreCase)), "Audit binder should include compliance review checklist CSV.");
    Assert(files.Any(x => Path.GetFileName(x).Equals("compliance_exceptions.csv", StringComparison.OrdinalIgnoreCase)), "Audit binder should include compliance exceptions CSV.");
    Assert(files.Any(x => Path.GetFileName(x).Equals("compliance_attestations.csv", StringComparison.OrdinalIgnoreCase)), "Audit binder should include compliance attestations CSV.");
    Assert(files.Any(x => Path.GetFileName(x).Equals("unallowable_costs.csv", StringComparison.OrdinalIgnoreCase)), "Audit binder should include unallowable costs CSV.");
    Assert(files.Any(x => Path.GetFileName(x).Equals("unallowable_costs.json", StringComparison.OrdinalIgnoreCase)), "Audit binder should include unallowable costs JSON.");
}

static string GenerateAuditBinder(
    TestScope s,
    DateOnly periodStart,
    DateOnly periodEnd,
    Guid contractId,
    ReportingService reporting,
    CloseService close,
    BillingService billing,
    IndirectRateService indirect,
    MonthlyCloseComplianceService monthlyClose,
    InternalAuditService internalAudit)
{
    var root = Path.Combine(
        Directory.GetCurrentDirectory(),
        "GovConMoney.Tests",
        "Runner",
        "AuditBinderOutput",
        $"{DateTime.UtcNow:yyyyMMdd_HHmmss}_{Guid.NewGuid():N}");
    Directory.CreateDirectory(root);

    var timesheetPacket = s.Store.Timesheets
        .Where(x => x.TenantId == s.Seed.TenantId && x.PeriodStart <= periodEnd && x.PeriodEnd >= periodStart)
        .Select(x => new TimesheetPacketRow(
            x.Id,
            x.UserId,
            x.PeriodStart,
            x.PeriodEnd,
            x.Status.ToString(),
            x.VersionNumber,
            x.SubmittedAtUtc,
            x.ApprovedAtUtc,
            x.PostedAtUtc,
            s.Store.TimesheetApprovals.Count(a => a.TimesheetId == x.Id),
            s.Store.CorrectionRequests.Count(c => c.TimesheetId == x.Id)))
        .OrderBy(x => x.PeriodStart)
        .ThenBy(x => x.TimesheetId)
        .ToList();

    var auditRows = reporting.SearchAudit(null, null);
    var managerReviewRows = auditRows
        .Where(x =>
            (!string.IsNullOrWhiteSpace(x.ActorRoles) && x.ActorRoles.Contains("Manager", StringComparison.OrdinalIgnoreCase)) ||
            ((x.EntityType == "RateCalculation" || x.EntityType == "BillingRun" || x.EntityType == "JournalEntry" || x.EntityType == "AccountingPeriod" || x.EntityType == "InternalAuditCycle" || x.EntityType == "InternalAuditAttestation")
             && (x.EventType == EventType.Submit || x.EventType == EventType.Approve || x.EventType == EventType.Reject)))
        .ToList();
    var laborRows = reporting.LaborDistribution();
    var projectRows = reporting.ProjectSummary();
    var complianceRows = reporting.TimesheetCompliance();
    var clinRows = reporting.ClinSummary(periodStart, periodEnd, contractId);
    var journalRows = reporting.GeneralJournal(periodStart, periodEnd);
    var trialBalanceRows = close.TrialBalance(periodStart, periodEnd);
    var tieOutRows = close.SubledgerToGlReconciliation(periodStart, periodEnd);
    var monthlyCloseRows = monthlyClose.CloseCadenceStatus(periodEnd, 10);
    var internalAuditComplianceRows = internalAudit.ComplianceReport(periodEnd);
    var internalAuditCycleRows = internalAudit.Cycles();
    var internalAuditAttestationRows = internalAudit.Attestations();
    var complianceReviewSummaryRows = internalAuditComplianceRows;
    var complianceReviewChecklistRows = internalAudit.Checklist();
    var complianceExceptionRows = internalAudit.Exceptions();
    var complianceAttestationRows = internalAuditAttestationRows;
    var indirectRateRows = indirect.RateSupport(periodStart, periodEnd);
    var indirectBurdenRows = indirect.BurdenSummary(periodStart, periodEnd);
    var billedToBookedRows = billing.BilledToBookedReconciliation(periodStart, periodEnd, contractId);

    var contracts = s.Store.Contracts.Where(x => x.TenantId == s.Seed.TenantId).ToDictionary(x => x.Id, x => x);
    var taskOrders = s.Store.TaskOrders.Where(x => x.TenantId == s.Seed.TenantId).ToDictionary(x => x.Id, x => x);
    var clins = s.Store.Clins.Where(x => x.TenantId == s.Seed.TenantId).ToDictionary(x => x.Id, x => x);
    var wbsNodes = s.Store.WbsNodes.Where(x => x.TenantId == s.Seed.TenantId).ToDictionary(x => x.Id, x => x);
    var chargeCodes = s.Store.ChargeCodes.Where(x => x.TenantId == s.Seed.TenantId).ToDictionary(x => x.Id, x => x);
    var users = s.Store.Users.Where(x => x.TenantId == s.Seed.TenantId).ToDictionary(x => x.Id, x => x.UserName);
    var rates = s.Store.PersonnelProfiles.Where(x => x.TenantId == s.Seed.TenantId).ToDictionary(x => x.UserId, x => x.HourlyRate);
    var postedSheetById = s.Store.Timesheets
        .Where(x => x.TenantId == s.Seed.TenantId)
        .Where(x => x.PostedAtUtc.HasValue)
        .Where(x => x.PeriodStart <= periodEnd && x.PeriodEnd >= periodStart)
        .ToDictionary(x => x.Id, x => x);

    var unallowableRows = new List<UnallowableCostRow>();

    foreach (var line in s.Store.TimesheetLines
        .Where(x => x.TenantId == s.Seed.TenantId)
        .Where(x => postedSheetById.ContainsKey(x.TimesheetId))
        .Where(x => x.WorkDate >= periodStart && x.WorkDate <= periodEnd)
        .Where(x => x.CostType == CostType.Unallowable))
    {
        var sheet = postedSheetById[line.TimesheetId];
        var hourlyRate = rates.TryGetValue(sheet.UserId, out var rate) ? rate : 0m;
        var amount = Math.Round((line.Minutes / 60m) * hourlyRate, 2);
        if (amount == 0m)
        {
            continue;
        }

        var (contractNumber, taskOrderNumber, clinNumber, wbsCode, chargeCode) = ResolveChargeHierarchy(line.ChargeCodeId);
        unallowableRows.Add(new UnallowableCostRow(
            "TimesheetLine",
            line.Id,
            line.TimesheetId,
            line.WorkDate,
            users.TryGetValue(sheet.UserId, out var userName) ? userName : sheet.UserId.ToString(),
            chargeCode,
            contractNumber,
            taskOrderNumber,
            clinNumber,
            wbsCode,
            line.CostType.ToString(),
            "N/A",
            amount,
            true,
            "CostType=Unallowable"));
    }

    foreach (var expense in s.Store.TimesheetExpenses
        .Where(x => x.TenantId == s.Seed.TenantId)
        .Where(x => postedSheetById.ContainsKey(x.TimesheetId))
        .Where(x => x.ExpenseDate >= periodStart && x.ExpenseDate <= periodEnd)
        .Where(x => x.Status == ExpenseStatus.Approved)
        .Where(x => x.CostType == CostType.Unallowable || x.AccountingCategory == ExpenseAccountingCategory.Unallowable))
    {
        if (expense.Amount == 0m)
        {
            continue;
        }

        var sheet = postedSheetById[expense.TimesheetId];
        var (contractNumber, taskOrderNumber, clinNumber, wbsCode, chargeCode) = ResolveChargeHierarchy(expense.ChargeCodeId);
        var exclusionBasis = expense.CostType == CostType.Unallowable && expense.AccountingCategory == ExpenseAccountingCategory.Unallowable
            ? "CostType=Unallowable;AccountingCategory=Unallowable"
            : expense.CostType == CostType.Unallowable
                ? "CostType=Unallowable"
                : "AccountingCategory=Unallowable";

        unallowableRows.Add(new UnallowableCostRow(
            "TimesheetExpense",
            expense.Id,
            expense.TimesheetId,
            expense.ExpenseDate,
            users.TryGetValue(sheet.UserId, out var userName) ? userName : sheet.UserId.ToString(),
            chargeCode,
            contractNumber,
            taskOrderNumber,
            clinNumber,
            wbsCode,
            expense.CostType.ToString(),
            expense.AccountingCategory.ToString(),
            Math.Round(expense.Amount, 2),
            true,
            exclusionBasis));
    }

    unallowableRows = unallowableRows
        .OrderBy(x => x.EntryDate)
        .ThenBy(x => x.Employee)
        .ThenBy(x => x.SourceEntityType)
        .ThenBy(x => x.SourceEntityId)
        .ToList();

    var invoiceRows = s.Store.Invoices
        .Where(x => x.TenantId == s.Seed.TenantId && x.PeriodStart == periodStart && x.PeriodEnd == periodEnd)
        .OrderBy(x => x.InvoiceNumber)
        .ToList();
    var invoiceLineRows = s.Store.InvoiceLines
        .Where(x => x.TenantId == s.Seed.TenantId)
        .OrderBy(x => x.InvoiceId)
        .ThenBy(x => x.ChargeCodeId)
        .ToList();
    var billedCostLinkRows = s.Store.BilledCostLinks
        .Where(x => x.TenantId == s.Seed.TenantId)
        .OrderBy(x => x.InvoiceLineId)
        .ToList();
    var adjustingPacketRows = s.Store.JournalEntries
        .Where(x => x.TenantId == s.Seed.TenantId && x.EntryType == JournalEntryType.Adjusting)
        .Select(x => new AdjustingPacketRow(
            x.Id,
            x.EntryDate,
            x.Status.ToString(),
            x.IsReversal,
            x.ReversalOfJournalEntryId,
            x.RequestedByUserId,
            x.ApprovedByUserId,
            x.PostedAtUtc,
            x.Reason,
            x.AttachmentRefs,
            s.Store.JournalLines.Count(l => l.JournalEntryId == x.Id),
            s.Store.JournalEntryApprovals.Count(a => a.JournalEntryId == x.Id)))
        .OrderBy(x => x.EntryDate)
        .ThenBy(x => x.JournalEntryId)
        .ToList();

    WriteArtifact(root, "timesheets_packet", timesheetPacket);
    WriteArtifact(root, "labor_distribution", laborRows);
    WriteArtifact(root, "project_summary", projectRows);
    WriteArtifact(root, "timesheet_compliance", complianceRows);
    WriteArtifact(root, "clin_summary", clinRows);
    WriteArtifact(root, "indirect_rate_support", indirectRateRows);
    WriteArtifact(root, "applied_burden_summary", indirectBurdenRows);
    WriteArtifact(root, "trial_balance", trialBalanceRows);
    WriteArtifact(root, "general_journal", journalRows);
    WriteArtifact(root, "subledger_gl_tieout", tieOutRows);
    WriteArtifact(root, "monthly_close_compliance", monthlyCloseRows);
    WriteArtifact(root, "internal_audit_compliance", internalAuditComplianceRows);
    WriteArtifact(root, "internal_audit_cycles", internalAuditCycleRows);
    WriteArtifact(root, "internal_audit_attestations", internalAuditAttestationRows);
    WriteArtifact(root, "compliance_review_summary", complianceReviewSummaryRows);
    WriteArtifact(root, "compliance_review_checklist", complianceReviewChecklistRows);
    WriteArtifact(root, "compliance_exceptions", complianceExceptionRows);
    WriteArtifact(root, "compliance_attestations", complianceAttestationRows);
    WriteArtifact(root, "unallowable_costs", unallowableRows);
    WriteArtifact(root, "invoices", invoiceRows);
    WriteArtifact(root, "invoice_lines", invoiceLineRows);
    WriteArtifact(root, "billed_cost_links", billedCostLinkRows);
    WriteArtifact(root, "billed_to_booked_reconciliation", billedToBookedRows);
    WriteArtifact(root, "adjusting_je_packet", adjustingPacketRows);
    WriteArtifact(root, "manager_review_events", managerReviewRows);
    WriteArtifact(root, "audit_trail", auditRows);

    File.WriteAllText(Path.Combine(root, "README.txt"),
        $"Audit binder generated UTC {DateTime.UtcNow:O}{Environment.NewLine}" +
        $"Tenant: {s.Seed.TenantId}{Environment.NewLine}" +
        $"Period: {periodStart:yyyy-MM-dd} to {periodEnd:yyyy-MM-dd}{Environment.NewLine}");

    return root;

    (string ContractNumber, string TaskOrderNumber, string ClinNumber, string WbsCode, string ChargeCode) ResolveChargeHierarchy(Guid chargeCodeId)
    {
        if (!chargeCodes.TryGetValue(chargeCodeId, out var chargeCode))
        {
            return ("(unknown)", "(unknown)", "(unknown)", "(unknown)", "(unknown)");
        }

        if (!wbsNodes.TryGetValue(chargeCode.WbsNodeId, out var wbs))
        {
            return ("(unknown)", "(unknown)", "(unknown)", "(unknown)", chargeCode.Code);
        }

        if (!clins.TryGetValue(wbs.ClinId, out var clin))
        {
            return ("(unknown)", "(unknown)", "(unknown)", wbs.Code, chargeCode.Code);
        }

        if (!taskOrders.TryGetValue(clin.TaskOrderId, out var taskOrder))
        {
            return ("(unknown)", "(unknown)", clin.Number, wbs.Code, chargeCode.Code);
        }

        return (
            contracts.TryGetValue(taskOrder.ContractId, out var contract) ? contract.ContractNumber : "(unknown)",
            taskOrder.Number,
            clin.Number,
            wbs.Code,
            chargeCode.Code);
    }
}

static InternalAuditCycle CreateReviewCycleForInternalAuditTests(TestScope s, InternalAuditService internalAudit)
{
    s.TenantContext.UserId = s.Seed.AccountantUserId;
    s.TenantContext.Roles = new[] { "Accountant" };

    var periodStart = DateOnly.FromDateTime(DateTime.UtcNow.Date.AddDays(-62));
    var periodEnd = DateOnly.FromDateTime(DateTime.UtcNow.Date.AddDays(-32));
    var period = new AccountingPeriod
    {
        TenantId = s.Seed.TenantId,
        StartDate = periodStart,
        EndDate = periodEnd,
        Status = AccountingPeriodStatus.Open
    };
    s.Store.AccountingPeriods.Add(period);
    s.Store.SaveChanges();

    internalAudit.SyncCycles(DateOnly.FromDateTime(DateTime.UtcNow.Date));
    return s.Store.InternalAuditCycles.Single(x => x.AccountingPeriodId == period.Id);
}

static void SetAllChecklistItems(InternalAuditService internalAudit, Guid cycleId, ComplianceChecklistResult result, string? note)
{
    var items = internalAudit.AutoPopulateChecklistFromClauseMatrix(new AutoPopulateInternalAuditChecklistRequest(cycleId));
    foreach (var item in items)
    {
        internalAudit.UpsertChecklistItem(new UpsertInternalAuditChecklistItemRequest(cycleId, item.Id, result, note));
    }
}

static void WriteArtifact<T>(string root, string stem, IReadOnlyList<T> rows)
{
    File.WriteAllText(Path.Combine(root, $"{stem}.json"), ExportService.ToJson(rows));
    File.WriteAllText(Path.Combine(root, $"{stem}.csv"), ExportService.ToCsv(rows));
}

static void Assert(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}

static void ExpectThrows<T>(Action action) where T : Exception
{
    try
    {
        action();
    }
    catch (T)
    {
        return;
    }

    throw new InvalidOperationException($"Expected exception {typeof(T).Name} was not thrown.");
}

sealed class FixedClock(DateTime utcNow) : GovConMoney.Application.Abstractions.IClock
{
    public DateTime UtcNow { get; } = utcNow;
}

sealed record TestScope(
    InMemoryDataStore Store,
    SeedContext Seed,
    TenantContextAccessor TenantContext,
    InMemoryRepository Repository,
    InMemoryAuditService Audit,
    NotificationService Notifications,
    CorrelationContext Correlation,
    FixedClock Clock,
    InMemoryTransaction Transaction);

sealed record TimesheetPacketRow(
    Guid TimesheetId,
    Guid UserId,
    DateOnly PeriodStart,
    DateOnly PeriodEnd,
    string Status,
    int VersionNumber,
    DateTime? SubmittedAtUtc,
    DateTime? ApprovedAtUtc,
    DateTime? PostedAtUtc,
    int ApprovalCount,
    int CorrectionCount);

sealed record AdjustingPacketRow(
    Guid JournalEntryId,
    DateOnly EntryDate,
    string Status,
    bool IsReversal,
    Guid? ReversalOfJournalEntryId,
    Guid? RequestedByUserId,
    Guid? ApprovedByUserId,
    DateTime? PostedAtUtc,
    string? Reason,
    string? AttachmentRefs,
    int JournalLineCount,
    int ApprovalCount);

sealed record UnallowableCostRow(
    string SourceEntityType,
    Guid SourceEntityId,
    Guid TimesheetId,
    DateOnly EntryDate,
    string Employee,
    string ChargeCode,
    string ContractNumber,
    string TaskOrderNumber,
    string ClinNumber,
    string WbsCode,
    string CostType,
    string AccountingCategory,
    decimal Amount,
    bool ExcludedFromBilling,
    string ExclusionBasis);
