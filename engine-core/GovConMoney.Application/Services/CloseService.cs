using GovConMoney.Application.Abstractions;
using GovConMoney.Application.Models;
using GovConMoney.Domain.Entities;
using GovConMoney.Domain.Enums;
using System.Text.Json;

namespace GovConMoney.Application.Services;

public sealed class CloseService(
    IRepository repository,
    ITenantContext tenantContext,
    IAuditService audit,
    ICorrelationContext correlation,
    IClock clock,
    IAppTransaction transaction)
{
    public IReadOnlyList<TrialBalanceRow> TrialBalance(DateOnly periodStart, DateOnly periodEnd)
    {
        if (periodEnd < periodStart)
        {
            throw new DomainRuleException("Trial balance period end must be on or after period start.");
        }

        var entries = repository.Query<JournalEntry>(tenantContext.TenantId)
            .Where(x => x.EntryDate >= periodStart && x.EntryDate <= periodEnd)
            .ToList();
        if (entries.Count == 0)
        {
            return [];
        }

        var entryIds = entries.Select(x => x.Id).ToHashSet();
        var accountById = repository.Query<ChartOfAccount>(tenantContext.TenantId)
            .ToDictionary(x => x.Id);

        return repository.Query<JournalLine>(tenantContext.TenantId)
            .Where(x => entryIds.Contains(x.JournalEntryId))
            .ToList()
            .GroupBy(x => x.AccountId)
            .Select(g =>
            {
                var account = accountById[g.Key];
                var debit = Math.Round(g.Sum(x => x.Debit), 2);
                var credit = Math.Round(g.Sum(x => x.Credit), 2);
                return new TrialBalanceRow(
                    account.AccountNumber,
                    account.Name,
                    debit,
                    credit,
                    Math.Round(debit - credit, 2));
            })
            .OrderBy(x => x.AccountNumber)
            .ToList();
    }

    public IReadOnlyList<SubledgerGlReconciliationRow> SubledgerToGlReconciliation(DateOnly periodStart, DateOnly periodEnd)
    {
        if (periodEnd < periodStart)
        {
            throw new DomainRuleException("Reconciliation period end must be on or after period start.");
        }

        var rows = new List<SubledgerGlReconciliationRow>();
        rows.Add(ReconcileLabor(periodStart, periodEnd));
        rows.Add(ReconcileExpenses(periodStart, periodEnd));
        rows.Add(ReconcileBurden(periodStart, periodEnd));
        return rows;
    }

    public IReadOnlyList<CloseValidationStepRow> PreCloseValidation(DateOnly periodStart, DateOnly periodEnd)
    {
        if (periodEnd < periodStart)
        {
            throw new DomainRuleException("Validation period end must be on or after period start.");
        }

        var steps = new List<CloseValidationStepRow>();
        var timesheets = repository.Query<Timesheet>(tenantContext.TenantId)
            .Where(x => x.PeriodStart <= periodEnd && x.PeriodEnd >= periodStart)
            .ToList();
        var unapproved = timesheets.Count(x => x.Status == TimesheetStatus.Draft || x.Status == TimesheetStatus.Submitted);
        steps.Add(new CloseValidationStepRow(
            "TimesheetsApproved",
            unapproved == 0,
            unapproved == 0 ? "All timesheets are approved/corrected." : $"{unapproved} timesheet(s) still draft/submitted."));

        var approvedNotPosted = timesheets.Count(x => x.Status == TimesheetStatus.Approved && !x.PostedAtUtc.HasValue);
        steps.Add(new CloseValidationStepRow(
            "ApprovedTimesheetsPosted",
            approvedNotPosted == 0,
            approvedNotPosted == 0 ? "No approved-unposted timesheets." : $"{approvedNotPosted} approved timesheet(s) not posted."));

        var payrollBatches = repository.Query<PayrollBatch>(tenantContext.TenantId)
            .Where(x => x.PeriodStart <= periodEnd && x.PeriodEnd >= periodStart)
            .ToList();
        steps.Add(new CloseValidationStepRow(
            "PayrollImported",
            payrollBatches.Count > 0,
            payrollBatches.Count > 0 ? $"{payrollBatches.Count} payroll batch(es) in period." : "No payroll batch imported for period."));

        var burdenApplied = repository.Query<AppliedBurdenEntry>(tenantContext.TenantId)
            .Any(x => x.PeriodStart == periodStart && x.PeriodEnd == periodEnd);
        steps.Add(new CloseValidationStepRow(
            "IndirectApplied",
            burdenApplied,
            burdenApplied ? "Applied burden entries exist for period." : "No applied burden entries for period."));

        var trialBalance = TrialBalance(periodStart, periodEnd);
        var totalDebit = Math.Round(trialBalance.Sum(x => x.Debit), 2);
        var totalCredit = Math.Round(trialBalance.Sum(x => x.Credit), 2);
        var balanced = totalDebit == totalCredit;
        steps.Add(new CloseValidationStepRow(
            "TrialBalanceBalanced",
            balanced,
            balanced ? "Trial balance is balanced." : $"Trial balance out of balance by {Math.Round(totalDebit - totalCredit, 2)}."));

        var tieOuts = SubledgerToGlReconciliation(periodStart, periodEnd);
        var tieOutPassed = tieOuts.All(x => string.Equals(x.Status, "Matched", StringComparison.OrdinalIgnoreCase));
        steps.Add(new CloseValidationStepRow(
            "SubledgerTieOutsComplete",
            tieOutPassed,
            tieOutPassed ? "All subledger-to-GL reconciliations matched." : "One or more tie-outs have variance."));

        return steps;
    }

    public void ClosePeriod(Guid accountingPeriodId, string? notes)
    {
        var period = repository.Query<AccountingPeriod>(tenantContext.TenantId)
            .SingleOrDefault(x => x.Id == accountingPeriodId)
            ?? throw new DomainRuleException("Accounting period not found.");

        if (!tenantContext.Roles.Contains("Manager", StringComparer.OrdinalIgnoreCase))
        {
            audit.Record(new AuditEvent
            {
                TenantId = tenantContext.TenantId,
                EntityType = "AccountingPeriod",
                EntityId = period.Id,
                EventType = EventType.Reject,
                ActorUserId = tenantContext.UserId,
                ActorRoles = string.Join(',', tenantContext.Roles),
                OccurredAtUtc = clock.UtcNow,
                ReasonForChange = "Period close attempt denied: manager role required.",
                BeforeJson = JsonSerializer.Serialize(new { period.Id, period.Status }),
                AfterJson = null,
                CorrelationId = correlation.CorrelationId
            });
            throw new DomainRuleException("Only managers can close accounting periods.");
        }

        var checks = PreCloseValidation(period.StartDate, period.EndDate);
        var failed = checks.Where(x => !x.Passed).ToList();
        if (failed.Count > 0)
        {
            audit.Record(new AuditEvent
            {
                TenantId = tenantContext.TenantId,
                EntityType = "AccountingPeriod",
                EntityId = period.Id,
                EventType = EventType.Reject,
                ActorUserId = tenantContext.UserId,
                ActorRoles = string.Join(',', tenantContext.Roles),
                OccurredAtUtc = clock.UtcNow,
                ReasonForChange = $"Period close attempt failed validation: {string.Join(", ", failed.Select(x => x.Step))}",
                BeforeJson = JsonSerializer.Serialize(new { period.Id, period.Status }),
                AfterJson = JsonSerializer.Serialize(new { FailedSteps = failed.Select(x => x.Step).ToList() }),
                CorrelationId = correlation.CorrelationId
            });
            throw new DomainRuleException($"Cannot close period. Failed checks: {string.Join("; ", failed.Select(x => x.Step))}");
        }

        var checklist = new CloseChecklist
        {
            TenantId = tenantContext.TenantId,
            AccountingPeriodId = period.Id,
            CompletedAtUtc = clock.UtcNow,
            CompletedByUserId = tenantContext.UserId,
            StepsJson = JsonSerializer.Serialize(checks),
            Notes = string.IsNullOrWhiteSpace(notes) ? null : notes.Trim()
        };

        var before = new { period.Id, period.Status };
        period.Status = AccountingPeriodStatus.Closed;
        transaction.Execute(() =>
        {
            repository.Update(period);
            repository.Add(checklist);
            audit.Record(new AuditEvent
            {
                TenantId = tenantContext.TenantId,
                EntityType = "AccountingPeriod",
                EntityId = period.Id,
                EventType = EventType.AccountingPeriodChange,
                ActorUserId = tenantContext.UserId,
                ActorRoles = string.Join(',', tenantContext.Roles),
                OccurredAtUtc = clock.UtcNow,
                ReasonForChange = "Closed period through period close workflow.",
                BeforeJson = JsonSerializer.Serialize(before),
                AfterJson = JsonSerializer.Serialize(new { PeriodId = period.Id, period.Status, ChecklistId = checklist.Id }),
                CorrelationId = correlation.CorrelationId
            });
        });
    }

    private SubledgerGlReconciliationRow ReconcileLabor(DateOnly periodStart, DateOnly periodEnd)
    {
        var ratesByUser = repository.Query<PersonnelProfile>(tenantContext.TenantId)
            .ToDictionary(x => x.UserId, x => x.HourlyRate);
        var timesheets = repository.Query<Timesheet>(tenantContext.TenantId)
            .Where(x => x.PostedAtUtc.HasValue && x.PeriodStart <= periodEnd && x.PeriodEnd >= periodStart)
            .ToDictionary(x => x.Id);
        var subledger = repository.Query<TimesheetLine>(tenantContext.TenantId)
            .Where(x => timesheets.ContainsKey(x.TimesheetId))
            .ToList()
            .Where(x => x.WorkDate >= periodStart && x.WorkDate <= periodEnd)
            .Sum(x =>
            {
                var sheet = timesheets[x.TimesheetId];
                var rate = ratesByUser.TryGetValue(sheet.UserId, out var hourly) ? hourly : 0m;
                return Math.Round((x.Minutes / 60m) * rate, 2);
            });
        var gl = SumGlAccounts(periodStart, periodEnd, ["5000", "5100", "5200"]);
        var variance = Math.Round(gl - subledger, 2);
        return new SubledgerGlReconciliationRow("Labor", Math.Round(subledger, 2), gl, variance, Math.Abs(variance) < 0.01m ? "Matched" : "Variance");
    }

    private SubledgerGlReconciliationRow ReconcileExpenses(DateOnly periodStart, DateOnly periodEnd)
    {
        var postedSheetIds = repository.Query<Timesheet>(tenantContext.TenantId)
            .Where(x => x.PostedAtUtc.HasValue && x.PeriodStart <= periodEnd && x.PeriodEnd >= periodStart)
            .Select(x => x.Id)
            .ToHashSet();
        var subledger = repository.Query<TimesheetExpense>(tenantContext.TenantId)
            .Where(x => postedSheetIds.Contains(x.TimesheetId))
            .Where(x => x.ExpenseDate >= periodStart && x.ExpenseDate <= periodEnd)
            .Where(x => x.Status == ExpenseStatus.Approved)
            .ToList()
            .Sum(x => x.Amount);
        var gl = SumGlAccounts(periodStart, periodEnd, ["5400", "5500", "5600", "5700", "5800", "5900", "5950"]);
        var variance = Math.Round(gl - subledger, 2);
        return new SubledgerGlReconciliationRow("Expenses", Math.Round(subledger, 2), gl, variance, Math.Abs(variance) < 0.01m ? "Matched" : "Variance");
    }

    private SubledgerGlReconciliationRow ReconcileBurden(DateOnly periodStart, DateOnly periodEnd)
    {
        var subledger = repository.Query<AppliedBurdenEntry>(tenantContext.TenantId)
            .Where(x => x.PeriodStart == periodStart && x.PeriodEnd == periodEnd)
            .Where(x => x.PostedAtUtc.HasValue)
            .ToList()
            .Sum(x => x.BurdenAmount);
        var gl = SumGlAccounts(periodStart, periodEnd, ["6500", "6600", "6700"]);
        var variance = Math.Round(gl - subledger, 2);
        return new SubledgerGlReconciliationRow("Burden", Math.Round(subledger, 2), gl, variance, Math.Abs(variance) < 0.01m ? "Matched" : "Variance");
    }

    private decimal SumGlAccounts(DateOnly periodStart, DateOnly periodEnd, IReadOnlyList<string> accountNumbers)
    {
        var accountIds = repository.Query<ChartOfAccount>(tenantContext.TenantId)
            .Where(x => accountNumbers.Contains(x.AccountNumber))
            .Select(x => x.Id)
            .ToHashSet();
        if (accountIds.Count == 0)
        {
            return 0m;
        }

        var entryIds = repository.Query<JournalEntry>(tenantContext.TenantId)
            .Where(x => x.EntryDate >= periodStart && x.EntryDate <= periodEnd)
            .Select(x => x.Id)
            .ToHashSet();
        if (entryIds.Count == 0)
        {
            return 0m;
        }

        var lines = repository.Query<JournalLine>(tenantContext.TenantId)
            .Where(x => entryIds.Contains(x.JournalEntryId) && accountIds.Contains(x.AccountId))
            .ToList();
        return Math.Round(lines.Sum(x => x.Debit - x.Credit), 2);
    }
}
