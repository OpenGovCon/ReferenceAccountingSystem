using GovConMoney.Application.Abstractions;
using GovConMoney.Domain.Entities;
using GovConMoney.Domain.Enums;
using System.Text.Json;

namespace GovConMoney.Application.Services;

public sealed class AccountingService(
    IRepository repository,
    ITenantContext tenantContext,
    IAuditService audit,
    ICorrelationContext correlation,
    IClock clock,
    IAppTransaction transaction)
{
    public int PostApprovedTimeCardsToLedger()
    {
        EnsureDefaultAccounts();

        var timesheets = repository.Query<Timesheet>(tenantContext.TenantId)
            .Where(x => x.Status == TimesheetStatus.Approved && x.PostedAtUtc == null)
            .OrderBy(x => x.PeriodStart)
            .ThenBy(x => x.Id)
            .ToList();

        var accountByNumber = repository.Query<ChartOfAccount>(tenantContext.TenantId)
            .ToDictionary(x => x.AccountNumber, StringComparer.OrdinalIgnoreCase);

        var ratesByUser = repository.Query<PersonnelProfile>(tenantContext.TenantId)
            .ToDictionary(x => x.UserId, x => x.HourlyRate);

        var postedCount = 0;
        foreach (var timesheet in timesheets)
        {
            PostSingleTimesheet(timesheet, accountByNumber, ratesByUser);
            postedCount++;
        }

        return postedCount;
    }

    public int PostAppliedBurdenEntries(IReadOnlyList<Guid> appliedBurdenEntryIds)
    {
        if (appliedBurdenEntryIds.Count == 0)
        {
            return 0;
        }

        EnsureDefaultAccounts();
        var accountByNumber = repository.Query<ChartOfAccount>(tenantContext.TenantId)
            .ToDictionary(x => x.AccountNumber, StringComparer.OrdinalIgnoreCase);
        var poolById = repository.Query<IndirectPool>(tenantContext.TenantId).ToDictionary(x => x.Id);
        var entries = repository.Query<AppliedBurdenEntry>(tenantContext.TenantId)
            .Where(x => appliedBurdenEntryIds.Contains(x.Id))
            .Where(x => !x.PostedAtUtc.HasValue)
            .ToList();

        var postedCount = 0;
        foreach (var bucket in entries.GroupBy(x => x.RateCalculationId))
        {
            var postingDate = bucket.Max(x => x.PeriodEnd);
            EnsurePostingDateOpen(postingDate);
            var lineItems = new Dictionary<Guid, (decimal Debit, decimal Credit)>();
            foreach (var entry in bucket)
            {
                var pool = poolById[entry.IndirectPoolId];
                var debitAccountNumber = GetBurdenExpenseAccount(pool.Name);
                AddDebit(lineItems, accountByNumber[debitAccountNumber].Id, Math.Abs(entry.BurdenAmount));
                AddCredit(lineItems, accountByNumber["2300"].Id, Math.Abs(entry.BurdenAmount));
            }

            var totalDebit = Math.Round(lineItems.Sum(x => x.Value.Debit), 2);
            var totalCredit = Math.Round(lineItems.Sum(x => x.Value.Credit), 2);
            if (totalDebit != totalCredit)
            {
                throw new DomainRuleException("Applied burden posting is out of balance.");
            }

            transaction.Execute(() =>
            {
                var entry = new JournalEntry
                {
                    TenantId = tenantContext.TenantId,
                    EntryDate = postingDate,
                    Description = $"Applied indirect burden posting (RateCalculation {bucket.Key})",
                    EntryType = JournalEntryType.Burden,
                    Status = JournalEntryStatus.Posted,
                    PostedAtUtc = clock.UtcNow,
                    IsReversal = false
                };
                repository.Add(entry);

                foreach (var posting in lineItems.Where(x => x.Value.Debit != 0m || x.Value.Credit != 0m))
                {
                    repository.Add(new JournalLine
                    {
                        TenantId = tenantContext.TenantId,
                        JournalEntryId = entry.Id,
                        AccountId = posting.Key,
                        Debit = Math.Round(posting.Value.Debit, 2),
                        Credit = Math.Round(posting.Value.Credit, 2)
                    });
                }

                foreach (var burdenEntry in bucket)
                {
                    burdenEntry.PostedAtUtc = clock.UtcNow;
                    burdenEntry.PostedJournalEntryId = entry.Id;
                    repository.Update(burdenEntry);
                }

                audit.Record(new AuditEvent
                {
                    TenantId = tenantContext.TenantId,
                    EntityType = "RateCalculation",
                    EntityId = bucket.Key,
                    EventType = EventType.Post,
                    ActorUserId = tenantContext.UserId,
                    ActorRoles = string.Join(',', tenantContext.Roles),
                    OccurredAtUtc = clock.UtcNow,
                    ReasonForChange = "Posted applied burden entries to general ledger.",
                    AfterJson = JsonSerializer.Serialize(new
                    {
                        RateCalculationId = bucket.Key,
                        JournalEntryId = entry.Id,
                        EntryCount = bucket.Count(),
                        totalDebit,
                        totalCredit
                    }),
                    CorrelationId = correlation.CorrelationId
                });
            });

            postedCount += bucket.Count();
        }

        return postedCount;
    }

    private void PostSingleTimesheet(
        Timesheet timesheet,
        IReadOnlyDictionary<string, ChartOfAccount> accountByNumber,
        IReadOnlyDictionary<Guid, decimal> ratesByUser)
    {
        var entryDate = DateOnly.FromDateTime(timesheet.ApprovedAtUtc ?? clock.UtcNow);
        EnsurePostingDateOpen(entryDate);
        var lineItems = new Dictionary<Guid, (decimal Debit, decimal Credit)>();
        var lineTotal = 0m;
        var expenseTotal = 0m;

        var hourlyRate = ratesByUser.TryGetValue(timesheet.UserId, out var configuredRate) ? configuredRate : 0m;
        var timesheetLines = repository.Query<TimesheetLine>(tenantContext.TenantId)
            .Where(x => x.TimesheetId == timesheet.Id)
            .ToList();
        foreach (var line in timesheetLines)
        {
            var amount = Math.Round((line.Minutes / 60m) * hourlyRate, 2);
            if (amount == 0m)
            {
                continue;
            }

            var expenseAccount = accountByNumber[GetLaborExpenseAccount(line.CostType)];
            AddDebit(lineItems, expenseAccount.Id, amount);
            lineTotal += amount;
        }

        if (lineTotal > 0m)
        {
            AddCredit(lineItems, accountByNumber["2100"].Id, lineTotal); // Accrued payroll
        }

        var approvedExpenses = repository.Query<TimesheetExpense>(tenantContext.TenantId)
            .Where(x => x.TimesheetId == timesheet.Id && x.Status == ExpenseStatus.Approved)
            .ToList();
        foreach (var expense in approvedExpenses)
        {
            var amount = Math.Round(expense.Amount, 2);
            if (amount == 0m)
            {
                continue;
            }

            var expenseAccount = accountByNumber[GetExpenseAccount(expense.AccountingCategory)];
            AddDebit(lineItems, expenseAccount.Id, amount);
            expenseTotal += amount;
        }

        if (expenseTotal > 0m)
        {
            AddCredit(lineItems, accountByNumber["2000"].Id, expenseTotal); // AP clearing
        }

        if (lineItems.Count == 0)
        {
            return;
        }

        var totalDebit = Math.Round(lineItems.Sum(x => x.Value.Debit), 2);
        var totalCredit = Math.Round(lineItems.Sum(x => x.Value.Credit), 2);
        if (totalDebit != totalCredit)
        {
            throw new DomainRuleException("General ledger posting is out of balance.");
        }

        transaction.Execute(() =>
        {
            var entry = new JournalEntry
            {
                TenantId = tenantContext.TenantId,
                EntryDate = entryDate,
                Description = $"Approved time card posting: {timesheet.PeriodStart} - {timesheet.PeriodEnd} (Timesheet {timesheet.Id})",
                EntryType = JournalEntryType.Payroll,
                Status = JournalEntryStatus.Posted,
                PostedAtUtc = clock.UtcNow,
                IsReversal = false
            };
            repository.Add(entry);

            foreach (var posting in lineItems.Where(x => x.Value.Debit != 0m || x.Value.Credit != 0m))
            {
                repository.Add(new JournalLine
                {
                    TenantId = tenantContext.TenantId,
                    JournalEntryId = entry.Id,
                    AccountId = posting.Key,
                    Debit = Math.Round(posting.Value.Debit, 2),
                    Credit = Math.Round(posting.Value.Credit, 2)
                });
            }

            timesheet.PostedAtUtc = clock.UtcNow;
            timesheet.PostedJournalEntryId = entry.Id;
            repository.Update(timesheet);

            audit.Record(new AuditEvent
            {
                TenantId = tenantContext.TenantId,
                EntityType = "Timesheet",
                EntityId = timesheet.Id,
                EventType = EventType.Post,
                ActorUserId = tenantContext.UserId,
                ActorRoles = string.Join(',', tenantContext.Roles),
                OccurredAtUtc = clock.UtcNow,
                ReasonForChange = "Posted approved time card to general ledger.",
                AfterJson = JsonSerializer.Serialize(new
                {
                    timesheet.Id,
                    timesheet.PostedAtUtc,
                    timesheet.PostedJournalEntryId,
                    totalDebit,
                    totalCredit
                }),
                CorrelationId = correlation.CorrelationId
            });
        });
    }

    private void EnsureDefaultAccounts()
    {
        var existing = repository.Query<ChartOfAccount>(tenantContext.TenantId)
            .Select(x => x.AccountNumber)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var accountsToAdd = new[]
        {
            NewAccount("1000", "Cash", CostType.Direct),
            NewAccount("2000", "Accounts Payable Clearing", CostType.Indirect),
            NewAccount("2100", "Accrued Payroll", CostType.Indirect),
            NewAccount("2300", "Applied Indirect Burden Clearing", CostType.Indirect),
            NewAccount("5000", "Direct Labor Expense", CostType.Direct),
            NewAccount("5100", "Indirect Labor Expense", CostType.Indirect),
            NewAccount("5200", "Unallowable Labor Expense", CostType.Unallowable),
            NewAccount("5400", "Allowable Expense", CostType.Direct),
            NewAccount("5500", "G&A Expense", CostType.Indirect),
            NewAccount("5600", "Overhead Expense", CostType.Indirect),
            NewAccount("5700", "Fringe Expense", CostType.Indirect),
            NewAccount("5800", "ODC Expense", CostType.Direct),
            NewAccount("5900", "Material Expense", CostType.Direct),
            NewAccount("5950", "Unallowable Expense", CostType.Unallowable),
            NewAccount("6500", "Applied G&A Burden Expense", CostType.Indirect),
            NewAccount("6600", "Applied Overhead Burden Expense", CostType.Indirect),
            NewAccount("6700", "Applied Fringe Burden Expense", CostType.Indirect)
        };

        foreach (var account in accountsToAdd.Where(x => !existing.Contains(x.AccountNumber)))
        {
            repository.Add(account);
        }
    }

    private ChartOfAccount NewAccount(string accountNumber, string name, CostType costType)
    {
        return new ChartOfAccount
        {
            TenantId = tenantContext.TenantId,
            AccountNumber = accountNumber,
            Name = name,
            CostType = costType
        };
    }

    private static string GetLaborExpenseAccount(CostType costType)
    {
        return costType switch
        {
            CostType.Direct => "5000",
            CostType.Indirect => "5100",
            CostType.Unallowable => "5200",
            _ => "5000"
        };
    }

    private static string GetExpenseAccount(ExpenseAccountingCategory accountingCategory)
    {
        return accountingCategory switch
        {
            ExpenseAccountingCategory.Allowable => "5400",
            ExpenseAccountingCategory.Unallowable => "5950",
            ExpenseAccountingCategory.GAndA => "5500",
            ExpenseAccountingCategory.Overhead => "5600",
            ExpenseAccountingCategory.Fringe => "5700",
            ExpenseAccountingCategory.Odc => "5800",
            ExpenseAccountingCategory.Material => "5900",
            _ => "5400"
        };
    }

    private static string GetBurdenExpenseAccount(string poolName)
    {
        if (poolName.Contains("fringe", StringComparison.OrdinalIgnoreCase))
        {
            return "6700";
        }

        if (poolName.Contains("g&a", StringComparison.OrdinalIgnoreCase) || poolName.Contains("ga", StringComparison.OrdinalIgnoreCase))
        {
            return "6500";
        }

        return "6600";
    }

    private void EnsurePostingDateOpen(DateOnly entryDate)
    {
        var period = repository.Query<AccountingPeriod>(tenantContext.TenantId)
            .SingleOrDefault(x => entryDate >= x.StartDate && entryDate <= x.EndDate);
        if (period is not null && period.Status == AccountingPeriodStatus.Closed)
        {
            throw new DomainRuleException("Cannot post journal entries into a closed accounting period.");
        }
    }

    private static void AddDebit(IDictionary<Guid, (decimal Debit, decimal Credit)> entries, Guid accountId, decimal amount)
    {
        var current = entries.TryGetValue(accountId, out var existing) ? existing : (0m, 0m);
        entries[accountId] = (current.Item1 + amount, current.Item2);
    }

    private static void AddCredit(IDictionary<Guid, (decimal Debit, decimal Credit)> entries, Guid accountId, decimal amount)
    {
        var current = entries.TryGetValue(accountId, out var existing) ? existing : (0m, 0m);
        entries[accountId] = (current.Item1, current.Item2 + amount);
    }
}
