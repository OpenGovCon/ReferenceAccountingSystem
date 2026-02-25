using GovConMoney.Application.Abstractions;
using GovConMoney.Domain.Entities;
using GovConMoney.Domain.Enums;

namespace GovConMoney.Application.Services;

public sealed class TimecardValidationEngine(IRepository repository, ITenantContext tenantContext)
{
    public IReadOnlyList<string> ValidateDraftCreation(Guid userId, DateOnly periodStart, DateOnly periodEnd)
    {
        var issues = new List<string>();
        var config = GetConfiguration();
        var (expectedStart, expectedEnd) = GetWorkPeriodBounds(periodStart, config.WeekStartDay, config.PeriodLengthDays);

        var hasExisting = repository.Query<Timesheet>(tenantContext.TenantId)
            .Where(x => x.UserId == userId && x.Status != TimesheetStatus.Corrected)
            .ToList()
            .Any(x =>
            {
                var (peerStart, peerEnd) = GetWorkPeriodBounds(x.PeriodStart, config.WeekStartDay, config.PeriodLengthDays);
                return peerStart == expectedStart && peerEnd == expectedEnd;
            });
        if (hasExisting)
        {
            issues.Add("Only one time card is allowed per configured work period.");
        }

        return issues;
    }

    public IReadOnlyList<string> ValidateSubmission(Timesheet timesheet)
    {
        var issues = new List<string>();
        var config = GetConfiguration();
        var (expectedStart, expectedEnd) = GetWorkPeriodBounds(timesheet.PeriodStart, config.WeekStartDay, config.PeriodLengthDays);

        var peerTimesheets = repository.Query<Timesheet>(tenantContext.TenantId)
            .Where(x => x.UserId == timesheet.UserId && x.Id != timesheet.Id && x.Status != TimesheetStatus.Corrected)
            .ToList();

        var samePeriodPeers = peerTimesheets
            .Where(x =>
            {
                var (peerStart, peerEnd) = GetWorkPeriodBounds(x.PeriodStart, config.WeekStartDay, config.PeriodLengthDays);
                return peerStart == expectedStart && peerEnd == expectedEnd;
            })
            .ToList();
        if (samePeriodPeers.Count > 0)
        {
            issues.Add("Only one time card is allowed per configured work period.");
        }

        var submittedPeerIds = samePeriodPeers
            .Where(x => x.Status is TimesheetStatus.Submitted or TimesheetStatus.Approved)
            .Select(x => x.Id)
            .ToHashSet();

        if (submittedPeerIds.Count > 0)
        {
            var currentChargeCodes = repository.Query<TimesheetLine>(tenantContext.TenantId)
                .Where(x => x.TimesheetId == timesheet.Id)
                .Select(x => x.ChargeCodeId)
                .Concat(repository.Query<TimesheetExpense>(tenantContext.TenantId)
                    .Where(x => x.TimesheetId == timesheet.Id)
                    .Select(x => x.ChargeCodeId))
                .ToHashSet();

            var peerChargeCodes = repository.Query<TimesheetLine>(tenantContext.TenantId)
                .Where(x => submittedPeerIds.Contains(x.TimesheetId))
                .Select(x => x.ChargeCodeId)
                .Concat(repository.Query<TimesheetExpense>(tenantContext.TenantId)
                    .Where(x => submittedPeerIds.Contains(x.TimesheetId))
                    .Select(x => x.ChargeCodeId))
                .ToHashSet();

            var duplicateCostCenters = currentChargeCodes.Intersect(peerChargeCodes).Count();
            if (duplicateCostCenters > 0)
            {
                issues.Add("Duplicate cost center charging detected for the same work period.");
            }
        }

        issues.AddRange(ValidateDailyEntry(timesheet, config));
        issues.AddRange(ValidateOvertimeAuthorizations(timesheet));
        issues.AddRange(ValidateFuturePtoAuthorizations(timesheet));
        issues.AddRange(ValidateClinTracking(timesheet));
        return issues;
    }

    public (DateOnly Start, DateOnly End) CurrentWorkPeriod(DateOnly date)
    {
        var config = GetConfiguration();
        return GetWorkPeriodBounds(date, config.WeekStartDay, config.PeriodLengthDays);
    }

    private WorkPeriodConfiguration GetConfiguration()
    {
        return repository.Query<WorkPeriodConfiguration>(tenantContext.TenantId).FirstOrDefault()
            ?? new WorkPeriodConfiguration
            {
                TenantId = tenantContext.TenantId,
                WeekStartDay = (int)DayOfWeek.Monday,
                PeriodLengthDays = 7
            };
    }

    private static (DateOnly Start, DateOnly End) GetWorkPeriodBounds(DateOnly date, int weekStartDay, int periodLengthDays)
    {
        var normalizedStart = ((weekStartDay % 7) + 7) % 7;
        var delta = ((int)date.DayOfWeek - normalizedStart + 7) % 7;
        var start = date.AddDays(-delta);
        var length = periodLengthDays <= 0 ? 7 : periodLengthDays;
        var end = start.AddDays(length - 1);
        return (start, end);
    }

    private IReadOnlyList<string> ValidateDailyEntry(Timesheet timesheet, WorkPeriodConfiguration config)
    {
        if (!config.DailyEntryRequired || !config.DailyEntryHardFail)
        {
            return [];
        }

        var graceDays = Math.Max(0, config.DailyEntryGraceDays);
        var cutoff = DateOnly.FromDateTime(DateTime.UtcNow.Date).AddDays(-graceDays);
        var requiredDates = EnumerateRequiredDates(timesheet.PeriodStart, timesheet.PeriodEnd, cutoff, config.DailyEntryIncludeWeekends);
        if (requiredDates.Count == 0)
        {
            return [];
        }

        var workedDates = repository.Query<TimesheetLine>(tenantContext.TenantId)
            .Where(x => x.TimesheetId == timesheet.Id)
            .Select(x => x.WorkDate)
            .Distinct()
            .ToHashSet();
        var missingDates = requiredDates.Where(x => !workedDates.Contains(x)).ToList();
        if (missingDates.Count == 0)
        {
            return [];
        }

        var sample = string.Join(", ", missingDates.Take(3).Select(x => x.ToString("yyyy-MM-dd")));
        var suffix = missingDates.Count > 3 ? ", ..." : string.Empty;
        return [$"Daily entry requirement violated: {missingDates.Count} missing required day(s) by grace policy. Missing: {sample}{suffix}"];
    }

    private static List<DateOnly> EnumerateRequiredDates(DateOnly start, DateOnly end, DateOnly cutoff, bool includeWeekends)
    {
        var requiredDates = new List<DateOnly>();
        for (var date = start; date <= end && date <= cutoff; date = date.AddDays(1))
        {
            if (!includeWeekends && date.DayOfWeek is DayOfWeek.Saturday or DayOfWeek.Sunday)
            {
                continue;
            }

            requiredDates.Add(date);
        }

        return requiredDates;
    }

    private IReadOnlyList<string> ValidateClinTracking(Timesheet timesheet)
    {
        var issues = new List<string>();
        var contracts = repository.Query<Contract>(tenantContext.TenantId).ToDictionary(x => x.Id);
        if (!contracts.Values.Any(x => x.RequiresClinTracking))
        {
            return issues;
        }

        var taskOrders = repository.Query<TaskOrder>(tenantContext.TenantId).ToDictionary(x => x.Id);
        var clins = repository.Query<Clin>(tenantContext.TenantId).ToDictionary(x => x.Id);
        var wbs = repository.Query<WbsNode>(tenantContext.TenantId).ToDictionary(x => x.Id);
        var chargeCodes = repository.Query<ChargeCode>(tenantContext.TenantId).ToDictionary(x => x.Id);

        var chargedCodeIds = repository.Query<TimesheetLine>(tenantContext.TenantId)
            .Where(x => x.TimesheetId == timesheet.Id)
            .Select(x => x.ChargeCodeId)
            .Concat(repository.Query<TimesheetExpense>(tenantContext.TenantId)
                .Where(x => x.TimesheetId == timesheet.Id)
                .Select(x => x.ChargeCodeId))
            .Distinct()
            .ToList();

        foreach (var chargeCodeId in chargedCodeIds)
        {
            if (!chargeCodes.TryGetValue(chargeCodeId, out var code))
            {
                issues.Add($"Charge code {chargeCodeId} is missing.");
                continue;
            }

            if (!wbs.TryGetValue(code.WbsNodeId, out var wbsNode))
            {
                issues.Add($"Charge code {code.Code} is not mapped to a valid WBS node.");
                continue;
            }

            if (!clins.TryGetValue(wbsNode.ClinId, out var clin))
            {
                issues.Add($"Charge code {code.Code} is not mapped to a valid CLIN.");
                continue;
            }

            if (!taskOrders.TryGetValue(clin.TaskOrderId, out var taskOrder))
            {
                issues.Add($"Charge code {code.Code} is not mapped to a valid Task Order.");
                continue;
            }

            if (!contracts.TryGetValue(taskOrder.ContractId, out var contract))
            {
                issues.Add($"Charge code {code.Code} is not mapped to a valid Contract.");
                continue;
            }

            if (contract.RequiresClinTracking && string.IsNullOrWhiteSpace(clin.Number))
            {
                issues.Add($"Contract {contract.ContractNumber} requires CLIN tracking, but charge code {code.Code} does not resolve to a valid CLIN.");
            }
        }

        return issues;
    }

    private IReadOnlyList<string> ValidateOvertimeAuthorizations(Timesheet timesheet)
    {
        const int standardDailyMinutes = 8 * 60;
        var dailyTotals = repository.Query<TimesheetLine>(tenantContext.TenantId)
            .Where(x => x.TimesheetId == timesheet.Id)
            .Where(x => x.EntryType == TimesheetEntryType.Work)
            .GroupBy(x => x.WorkDate)
            .Select(x => new { WorkDate = x.Key, TotalMinutes = x.Sum(y => y.Minutes) })
            .Where(x => x.TotalMinutes > standardDailyMinutes)
            .ToList();
        if (dailyTotals.Count == 0)
        {
            return [];
        }

        var overtimeDates = dailyTotals.Select(x => x.WorkDate).ToHashSet();
        var approvedByDate = repository.Query<OvertimeAllowanceApproval>(tenantContext.TenantId)
            .Where(x => x.UserId == timesheet.UserId && overtimeDates.Contains(x.WorkDate))
            .ToList()
            .GroupBy(x => x.WorkDate)
            .ToDictionary(x => x.Key, x => x.Sum(y => y.ApprovedOvertimeMinutes));

        var issues = new List<string>();
        foreach (var day in dailyTotals.OrderBy(x => x.WorkDate))
        {
            var requiredOvertimeMinutes = day.TotalMinutes - standardDailyMinutes;
            var approvedOvertimeMinutes = approvedByDate.TryGetValue(day.WorkDate, out var approved) ? approved : 0;
            if (approvedOvertimeMinutes < requiredOvertimeMinutes)
            {
                issues.Add($"Overtime authorization required for {day.WorkDate:yyyy-MM-dd}: {requiredOvertimeMinutes} overtime minute(s) entered; {approvedOvertimeMinutes} approved.");
            }
        }

        return issues;
    }

    private IReadOnlyList<string> ValidateFuturePtoAuthorizations(Timesheet timesheet)
    {
        var today = DateOnly.FromDateTime(DateTime.UtcNow.Date);
        var futurePtoDates = repository.Query<TimesheetLine>(tenantContext.TenantId)
            .Where(x => x.TimesheetId == timesheet.Id)
            .Where(x => x.EntryType == TimesheetEntryType.Pto && x.WorkDate > today)
            .Select(x => x.WorkDate)
            .Distinct()
            .ToList();
        if (futurePtoDates.Count == 0)
        {
            return [];
        }

        var approvedDates = repository.Query<FuturePtoApproval>(tenantContext.TenantId)
            .Where(x => x.UserId == timesheet.UserId && futurePtoDates.Contains(x.WorkDate))
            .Select(x => x.WorkDate)
            .Distinct()
            .ToHashSet();

        var missingDates = futurePtoDates.Where(x => !approvedDates.Contains(x)).OrderBy(x => x).ToList();
        if (missingDates.Count == 0)
        {
            return [];
        }

        var sample = string.Join(", ", missingDates.Take(3).Select(x => x.ToString("yyyy-MM-dd")));
        var suffix = missingDates.Count > 3 ? ", ..." : string.Empty;
        return [$"Future PTO entries require supervisor approval before submission. Missing approval for: {sample}{suffix}"];
    }
}
