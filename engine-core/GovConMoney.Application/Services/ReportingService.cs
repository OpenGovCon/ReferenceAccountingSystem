using GovConMoney.Application.Abstractions;
using GovConMoney.Application.Models;
using GovConMoney.Domain.Entities;
using GovConMoney.Domain.Enums;
using System.Text;
using System.Text.Json;

namespace GovConMoney.Application.Services;

public class ReportingService(IRepository repository, ITenantContext tenantContext)
{
    public IReadOnlyList<LaborDistributionRow> LaborDistribution()
    {
        var users = repository.Query<AppUser>(tenantContext.TenantId).ToDictionary(x => x.Id, x => x.UserName);
        var chargeCodes = repository.Query<ChargeCode>(tenantContext.TenantId).ToDictionary(x => x.Id, x => x.Code);
        var rates = repository.Query<PersonnelProfile>(tenantContext.TenantId).ToDictionary(x => x.UserId, x => x.HourlyRate);
        var timesheets = repository.Query<Timesheet>(tenantContext.TenantId).ToDictionary(x => x.Id, x => x.UserId);
        var lines = repository.Query<TimesheetLine>(tenantContext.TenantId).ToList();

        return lines
            .GroupBy(x => new { x.ChargeCodeId, x.TimesheetId })
            .Select(g =>
            {
                var employeeId = timesheets[g.Key.TimesheetId];
                var minutes = g.Sum(x => x.Minutes);
                var rate = rates.TryGetValue(employeeId, out var hourlyRate) ? hourlyRate : 0m;
                return new LaborDistributionRow(users[employeeId], chargeCodes[g.Key.ChargeCodeId], minutes, Math.Round(rate * (minutes / 60m), 2));
            })
            .ToList();
    }

    public IReadOnlyList<ProjectSummaryRow> ProjectSummary()
    {
        var chargeCodes = repository.Query<ChargeCode>(tenantContext.TenantId).ToDictionary(x => x.Id);
        var wbsById = repository.Query<WbsNode>(tenantContext.TenantId).ToDictionary(x => x.Id);
        var clinById = repository.Query<Clin>(tenantContext.TenantId).ToDictionary(x => x.Id);
        var taskOrderById = repository.Query<TaskOrder>(tenantContext.TenantId).ToDictionary(x => x.Id);
        var contractById = repository.Query<Contract>(tenantContext.TenantId).ToDictionary(x => x.Id);
        var burdens = repository.Query<AppliedBurdenEntry>(tenantContext.TenantId).ToLookup(x => x.TimesheetLineId);

        var items = repository.Query<TimesheetLine>(tenantContext.TenantId)
            .ToList()
            .Select(line =>
            {
                var code = chargeCodes[line.ChargeCodeId];
                var wbs = wbsById[code.WbsNodeId];
                var clin = clinById[wbs.ClinId];
                var task = taskOrderById[clin.TaskOrderId];
                var contract = contractById[task.ContractId];
                var burden = burdens[line.Id].FirstOrDefault()?.BurdenAmount ?? 0m;
                return new { contract.ContractNumber, code.CostType, Direct = line.Minutes / 60m, Burden = burden };
            });

        return items.GroupBy(x => x.ContractNumber).Select(g =>
        {
            var direct = g.Where(x => x.CostType == CostType.Direct).Sum(x => x.Direct);
            var indirect = g.Where(x => x.CostType == CostType.Indirect).Sum(x => x.Burden);
            var unallowable = g.Where(x => x.CostType == CostType.Unallowable).Sum(x => x.Direct);
            return new ProjectSummaryRow(g.Key, Math.Round(direct, 2), Math.Round(indirect, 2), Math.Round(unallowable, 2));
        }).ToList();
    }

    public IReadOnlyList<TimesheetComplianceRow> TimesheetCompliance()
    {
        var users = repository.Query<AppUser>(tenantContext.TenantId).ToDictionary(x => x.Id, x => x.UserName);
        var periods = repository.Query<Timesheet>(tenantContext.TenantId).ToList();
        var linesByTimesheet = repository.Query<TimesheetLine>(tenantContext.TenantId).ToList().GroupBy(x => x.TimesheetId).ToDictionary(x => x.Key, x => x.ToList());
        var corrections = repository.Query<CorrectionRequest>(tenantContext.TenantId).ToList().GroupBy(x => x.TimesheetId).ToDictionary(x => x.Key, x => x.Count());
        var config = repository.Query<WorkPeriodConfiguration>(tenantContext.TenantId).FirstOrDefault() ?? new WorkPeriodConfiguration
        {
            TenantId = tenantContext.TenantId,
            WeekStartDay = (int)DayOfWeek.Monday,
            PeriodLengthDays = 7,
            DailyEntryRequired = true,
            DailyEntryGraceDays = 1,
            DailyEntryHardFail = true,
            DailyEntryIncludeWeekends = false
        };

        return periods.Select(t =>
        {
            var workedDates = linesByTimesheet.TryGetValue(t.Id, out var lines)
                ? lines.Select(x => x.WorkDate).Distinct().ToHashSet()
                : [];
            var requiredDates = GetRequiredDailyEntryDates(
                t.PeriodStart,
                t.PeriodEnd,
                config,
                t.SubmittedAtUtc?.Date ?? DateTime.UtcNow.Date);
            var dailyEntryViolations = config.DailyEntryRequired ? requiredDates.Count(d => !workedDates.Contains(d)) : 0;
            var late = (t.SubmittedAtUtc ?? DateTime.MinValue).Date > t.PeriodEnd.ToDateTime(TimeOnly.MinValue).Date ? 1 : 0;
            var correctionCount = corrections.TryGetValue(t.Id, out var c) ? c : 0;
            return new TimesheetComplianceRow(users[t.UserId], dailyEntryViolations, late, correctionCount, dailyEntryViolations);
        }).ToList();
    }

    private static IReadOnlyList<DateOnly> GetRequiredDailyEntryDates(
        DateOnly periodStart,
        DateOnly periodEnd,
        WorkPeriodConfiguration config,
        DateTime evaluationDateUtc)
    {
        if (!config.DailyEntryRequired)
        {
            return [];
        }

        var graceDays = Math.Max(0, config.DailyEntryGraceDays);
        var cutoff = DateOnly.FromDateTime(evaluationDateUtc.Date).AddDays(-graceDays);
        var requiredDates = new List<DateOnly>();
        for (var date = periodStart; date <= periodEnd && date <= cutoff; date = date.AddDays(1))
        {
            if (!config.DailyEntryIncludeWeekends && date.DayOfWeek is DayOfWeek.Saturday or DayOfWeek.Sunday)
            {
                continue;
            }

            requiredDates.Add(date);
        }

        return requiredDates;
    }

    public IReadOnlyList<AuditEvent> SearchAudit(string? entityType, EventType? eventType)
    {
        var query = repository.Query<AuditEvent>(tenantContext.TenantId);
        if (!string.IsNullOrWhiteSpace(entityType))
        {
            var normalizedEntityType = entityType.Trim().ToUpperInvariant();
            query = query.Where(x => x.EntityType.ToUpper() == normalizedEntityType);
        }
        if (eventType.HasValue)
        {
            query = query.Where(x => x.EventType == eventType.Value);
        }

        return query.OrderByDescending(x => x.OccurredAtUtc).ToList();
    }

    public IReadOnlyList<GeneralJournalRow> GeneralJournal(DateOnly? fromDate = null, DateOnly? toDate = null)
    {
        var entries = repository.Query<JournalEntry>(tenantContext.TenantId)
            .Where(x => x.Status == JournalEntryStatus.Posted)
            .AsQueryable();
        if (fromDate.HasValue)
        {
            entries = entries.Where(x => x.EntryDate >= fromDate.Value);
        }

        if (toDate.HasValue)
        {
            entries = entries.Where(x => x.EntryDate <= toDate.Value);
        }

        var entryList = entries
            .OrderByDescending(x => x.EntryDate)
            .ThenByDescending(x => x.Id)
            .ToList();
        if (entryList.Count == 0)
        {
            return [];
        }

        var entryIds = entryList.Select(x => x.Id).ToHashSet();
        var accountById = repository.Query<ChartOfAccount>(tenantContext.TenantId)
            .ToDictionary(x => x.Id);

        return repository.Query<JournalLine>(tenantContext.TenantId)
            .Where(x => entryIds.Contains(x.JournalEntryId))
            .ToList()
            .Join(
                entryList,
                line => line.JournalEntryId,
                entry => entry.Id,
                (line, entry) => new { line, entry })
            .Select(x =>
            {
                var account = accountById[x.line.AccountId];
                return new GeneralJournalRow(
                    x.entry.Id,
                    x.entry.EntryDate,
                    x.entry.Description,
                    account.AccountNumber,
                    account.Name,
                    x.line.Debit,
                    x.line.Credit);
            })
            .OrderByDescending(x => x.EntryDate)
            .ThenBy(x => x.JournalEntryId)
            .ThenBy(x => x.AccountNumber)
            .ToList();
    }

    public IReadOnlyList<ClinSummaryRow> ClinSummary(DateOnly periodStart, DateOnly periodEnd, Guid? contractId = null)
    {
        if (periodEnd < periodStart)
        {
            throw new DomainRuleException("CLIN summary period end must be on or after period start.");
        }

        var contracts = repository.Query<Contract>(tenantContext.TenantId).AsQueryable();
        if (contractId.HasValue)
        {
            contracts = contracts.Where(x => x.Id == contractId.Value);
        }

        var contractById = contracts.ToDictionary(x => x.Id);
        if (contractById.Count == 0)
        {
            return [];
        }
        var contractIds = contractById.Keys.ToList();

        var taskOrders = repository.Query<TaskOrder>(tenantContext.TenantId)
            .Where(x => contractIds.Contains(x.ContractId))
            .ToDictionary(x => x.Id);
        var taskOrderIds = taskOrders.Keys.ToList();
        var clins = repository.Query<Clin>(tenantContext.TenantId)
            .Where(x => taskOrderIds.Contains(x.TaskOrderId))
            .ToDictionary(x => x.Id);
        var clinIds = clins.Keys.ToList();
        var wbs = repository.Query<WbsNode>(tenantContext.TenantId)
            .Where(x => clinIds.Contains(x.ClinId))
            .ToDictionary(x => x.Id);
        var wbsIds = wbs.Keys.ToList();
        var chargeCodes = repository.Query<ChargeCode>(tenantContext.TenantId)
            .Where(x => wbsIds.Contains(x.WbsNodeId))
            .ToDictionary(x => x.Id);

        var hierarchyByChargeCode = chargeCodes
            .Select(x =>
            {
                var wbsNode = wbs[x.Value.WbsNodeId];
                var clin = clins[wbsNode.ClinId];
                var taskOrder = taskOrders[clin.TaskOrderId];
                var contract = contractById[taskOrder.ContractId];
                return new
                {
                    ChargeCodeId = x.Key,
                    Contract = contract,
                    TaskOrder = taskOrder,
                    Clin = clin,
                    Wbs = wbsNode,
                    ChargeCode = x.Value
                };
            })
            .ToDictionary(x => x.ChargeCodeId);

        var timesheets = repository.Query<Timesheet>(tenantContext.TenantId)
            .Where(x => x.PeriodStart <= periodEnd && x.PeriodEnd >= periodStart)
            .ToDictionary(x => x.Id);
        var timesheetIds = timesheets.Keys.ToList();
        var rates = repository.Query<PersonnelProfile>(tenantContext.TenantId).ToDictionary(x => x.UserId, x => x.HourlyRate);

        var laborRows = repository.Query<TimesheetLine>(tenantContext.TenantId)
            .Where(x => timesheetIds.Contains(x.TimesheetId))
            .ToList()
            .Where(x => x.WorkDate >= periodStart && x.WorkDate <= periodEnd)
            .Where(x => hierarchyByChargeCode.ContainsKey(x.ChargeCodeId))
            .Select(x =>
            {
                var hierarchy = hierarchyByChargeCode[x.ChargeCodeId];
                var timesheet = timesheets[x.TimesheetId];
                var hourlyRate = rates.TryGetValue(timesheet.UserId, out var rate) ? rate : 0m;
                var hours = Math.Round(x.Minutes / 60m, 2);
                var laborDollars = Math.Round(hours * hourlyRate, 2);
                return new
                {
                    ContractId = hierarchy.Contract.Id,
                    hierarchy.Contract.ContractNumber,
                    TaskOrderId = hierarchy.TaskOrder.Id,
                    TaskOrderNumber = hierarchy.TaskOrder.Number,
                    ClinId = hierarchy.Clin.Id,
                    ClinNumber = hierarchy.Clin.Number,
                    WbsNodeId = hierarchy.Wbs.Id,
                    WbsCode = hierarchy.Wbs.Code,
                    ChargeCodeId = hierarchy.ChargeCode.Id,
                    ChargeCode = hierarchy.ChargeCode.Code,
                    x.CostType,
                    LaborHours = hours,
                    LaborDollars = laborDollars,
                    ExpenseDollars = 0m,
                    AppliedBurdenDollars = 0m
                };
            });

        var expenseRows = repository.Query<TimesheetExpense>(tenantContext.TenantId)
            .Where(x => timesheetIds.Contains(x.TimesheetId))
            .Where(x => x.ExpenseDate >= periodStart && x.ExpenseDate <= periodEnd)
            .Where(x => x.Status == ExpenseStatus.Approved)
            .ToList()
            .Where(x => hierarchyByChargeCode.ContainsKey(x.ChargeCodeId))
            .Select(x =>
            {
                var hierarchy = hierarchyByChargeCode[x.ChargeCodeId];
                return new
                {
                    ContractId = hierarchy.Contract.Id,
                    hierarchy.Contract.ContractNumber,
                    TaskOrderId = hierarchy.TaskOrder.Id,
                    TaskOrderNumber = hierarchy.TaskOrder.Number,
                    ClinId = hierarchy.Clin.Id,
                    ClinNumber = hierarchy.Clin.Number,
                    WbsNodeId = hierarchy.Wbs.Id,
                    WbsCode = hierarchy.Wbs.Code,
                    ChargeCodeId = hierarchy.ChargeCode.Id,
                    ChargeCode = hierarchy.ChargeCode.Code,
                    x.CostType,
                    LaborHours = 0m,
                    LaborDollars = 0m,
                    ExpenseDollars = Math.Round(x.Amount, 2),
                    AppliedBurdenDollars = 0m
                };
            });

        var burdenRows = repository.Query<AppliedBurdenEntry>(tenantContext.TenantId)
            .Where(x => x.PeriodStart == periodStart && x.PeriodEnd == periodEnd)
            .ToList()
            .Where(x => hierarchyByChargeCode.ContainsKey(x.ChargeCodeId))
            .Select(x =>
            {
                var hierarchy = hierarchyByChargeCode[x.ChargeCodeId];
                return new
                {
                    ContractId = hierarchy.Contract.Id,
                    hierarchy.Contract.ContractNumber,
                    TaskOrderId = hierarchy.TaskOrder.Id,
                    TaskOrderNumber = hierarchy.TaskOrder.Number,
                    ClinId = hierarchy.Clin.Id,
                    ClinNumber = hierarchy.Clin.Number,
                    WbsNodeId = hierarchy.Wbs.Id,
                    WbsCode = hierarchy.Wbs.Code,
                    ChargeCodeId = hierarchy.ChargeCode.Id,
                    ChargeCode = hierarchy.ChargeCode.Code,
                    hierarchy.ChargeCode.CostType,
                    LaborHours = 0m,
                    LaborDollars = 0m,
                    ExpenseDollars = 0m,
                    AppliedBurdenDollars = Math.Round(x.BurdenAmount, 2)
                };
            });

        return laborRows
            .Concat(expenseRows)
            .Concat(burdenRows)
            .GroupBy(x => new
            {
                x.ContractId,
                x.ContractNumber,
                x.TaskOrderId,
                x.TaskOrderNumber,
                x.ClinId,
                x.ClinNumber,
                x.WbsNodeId,
                x.WbsCode,
                x.ChargeCodeId,
                x.ChargeCode,
                x.CostType
            })
            .Select(g => new ClinSummaryRow(
                g.Key.ContractId,
                g.Key.ContractNumber,
                g.Key.TaskOrderId,
                g.Key.TaskOrderNumber,
                g.Key.ClinId,
                g.Key.ClinNumber,
                g.Key.WbsNodeId,
                g.Key.WbsCode,
                g.Key.ChargeCodeId,
                g.Key.ChargeCode,
                g.Key.CostType,
                Math.Round(g.Sum(x => x.LaborHours), 2),
                Math.Round(g.Sum(x => x.LaborDollars), 2),
                Math.Round(g.Sum(x => x.ExpenseDollars), 2),
                Math.Round(g.Sum(x => x.AppliedBurdenDollars), 2),
                Math.Round(g.Sum(x => x.LaborDollars + x.ExpenseDollars + x.AppliedBurdenDollars), 2)))
            .OrderBy(x => x.ContractNumber)
            .ThenBy(x => x.TaskOrderNumber)
            .ThenBy(x => x.ClinNumber)
            .ThenBy(x => x.WbsCode)
            .ThenBy(x => x.ChargeCode)
            .ToList();
    }
}

public static class ExportService
{
    public static string ToJson<T>(IEnumerable<T> rows)
    {
        return JsonSerializer.Serialize(rows, new JsonSerializerOptions { WriteIndented = true });
    }

    public static string ToCsv<T>(IEnumerable<T> rows)
    {
        var list = rows.ToList();
        if (list.Count == 0)
        {
            return string.Empty;
        }

        var properties = typeof(T).GetProperties();
        var sb = new StringBuilder();
        sb.AppendLine(string.Join(',', properties.Select(p => p.Name)));

        foreach (var row in list)
        {
            sb.AppendLine(string.Join(',', properties.Select(p => Escape(p.GetValue(row)?.ToString() ?? string.Empty))));
        }

        return sb.ToString();
    }

    private static string Escape(string input)
    {
        if (input.Contains(',') || input.Contains('"') || input.Contains('\n'))
        {
            return "\"" + input.Replace("\"", "\"\"") + "\"";
        }

        return input;
    }
}
