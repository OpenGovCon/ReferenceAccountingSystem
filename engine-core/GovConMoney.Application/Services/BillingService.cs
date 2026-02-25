using GovConMoney.Application.Abstractions;
using GovConMoney.Application.Models;
using GovConMoney.Domain.Entities;
using GovConMoney.Domain.Enums;
using System.Text.Json;

namespace GovConMoney.Application.Services;

public sealed class BillingService(
    IRepository repository,
    ITenantContext tenantContext,
    IAuditService audit,
    ICorrelationContext correlation,
    IClock clock,
    IAppTransaction transaction,
    NotificationService notifications)
{
    public BillingCeiling UpsertCeiling(UpsertBillingCeilingRequest request)
    {
        EnsureAccountant();
        if (request.CeilingAmount < 0m || request.FundedAmount < 0m)
        {
            throw new DomainRuleException("Billing ceiling and funded amounts cannot be negative.");
        }

        if (request.EffectiveEndDate < request.EffectiveStartDate)
        {
            throw new DomainRuleException("Billing ceiling end date must be on or after start date.");
        }

        _ = repository.Query<Contract>(tenantContext.TenantId).SingleOrDefault(x => x.Id == request.ContractId)
            ?? throw new DomainRuleException("Contract not found.");

        var existing = repository.Query<BillingCeiling>(tenantContext.TenantId)
            .SingleOrDefault(x => x.ContractId == request.ContractId);

        if (existing is null)
        {
            var created = new BillingCeiling
            {
                TenantId = tenantContext.TenantId,
                ContractId = request.ContractId,
                FundedAmount = Math.Round(request.FundedAmount, 2),
                CeilingAmount = Math.Round(request.CeilingAmount, 2),
                EffectiveStartDate = request.EffectiveStartDate,
                EffectiveEndDate = request.EffectiveEndDate,
                IsActive = request.IsActive
            };
            transaction.Execute(() =>
            {
                repository.Add(created);
                RecordAudit("BillingCeiling", created.Id, EventType.Create, null, created, "Created billing ceiling.");
            });
            return created;
        }

        var before = JsonSerializer.Serialize(existing);
        existing.FundedAmount = Math.Round(request.FundedAmount, 2);
        existing.CeilingAmount = Math.Round(request.CeilingAmount, 2);
        existing.EffectiveStartDate = request.EffectiveStartDate;
        existing.EffectiveEndDate = request.EffectiveEndDate;
        existing.IsActive = request.IsActive;
        transaction.Execute(() =>
        {
            repository.Update(existing);
            RecordAudit("BillingCeiling", existing.Id, EventType.UpdateDraft, before, existing, "Updated billing ceiling.");
        });
        return existing;
    }

    public IReadOnlyList<BillingRunSummaryRow> BillingRuns()
    {
        EnsureManagerOrAccountant();
        var invoiceLookup = repository.Query<Invoice>(tenantContext.TenantId)
            .ToList()
            .ToLookup(x => x.BillingRunId);

        return repository.Query<BillingRun>(tenantContext.TenantId)
            .OrderByDescending(x => x.RunDateUtc)
            .ToList()
            .Select(x =>
            {
                var invoices = invoiceLookup[x.Id];
                return new BillingRunSummaryRow(
                    x.Id,
                    x.PeriodStart,
                    x.PeriodEnd,
                    x.Status.ToString(),
                    invoices.Count(),
                    Math.Round(invoices.Sum(i => i.TotalAmount), 2),
                    x.RunDateUtc);
            })
            .ToList();
    }

    public BillingRun GenerateBillingRun(CreateBillingRunRequest request)
    {
        EnsureAccountant();
        if (request.PeriodEnd < request.PeriodStart)
        {
            throw new DomainRuleException("Billing period end must be on or after start.");
        }

        var contractQuery = repository.Query<Contract>(tenantContext.TenantId).AsQueryable();
        if (request.ContractId.HasValue)
        {
            contractQuery = contractQuery.Where(x => x.Id == request.ContractId.Value);
        }

        var contracts = contractQuery.ToList();
        if (contracts.Count == 0)
        {
            throw new DomainRuleException("No contracts found for billing run.");
        }

        var run = new BillingRun
        {
            TenantId = tenantContext.TenantId,
            PeriodStart = request.PeriodStart,
            PeriodEnd = request.PeriodEnd,
            RunDateUtc = clock.UtcNow,
            Status = BillingRunStatus.Draft,
            CreatedByUserId = tenantContext.UserId,
            Notes = string.IsNullOrWhiteSpace(request.Notes) ? null : request.Notes.Trim()
        };

        var ratesByUser = repository.Query<PersonnelProfile>(tenantContext.TenantId)
            .ToDictionary(x => x.UserId, x => x.HourlyRate);
        var postedTimesheets = repository.Query<Timesheet>(tenantContext.TenantId)
            .Where(x => x.PostedAtUtc.HasValue)
            .Where(x => x.PeriodStart <= request.PeriodEnd && x.PeriodEnd >= request.PeriodStart)
            .ToDictionary(x => x.Id);
        var postedTimesheetIds = postedTimesheets.Keys.ToList();
        var chargeHierarchy = BuildChargeHierarchy();

        var laborCosts = repository.Query<TimesheetLine>(tenantContext.TenantId)
            .Where(x => postedTimesheetIds.Contains(x.TimesheetId))
            .ToList()
            .Where(x => x.WorkDate >= request.PeriodStart && x.WorkDate <= request.PeriodEnd)
            .Where(x => x.CostType != CostType.Unallowable)
            .Select(x =>
            {
                var sheet = postedTimesheets[x.TimesheetId];
                var rate = ratesByUser.TryGetValue(sheet.UserId, out var hourlyRate) ? hourlyRate : 0m;
                return new
                {
                    LineId = x.Id,
                    x.ChargeCodeId,
                    x.CostType,
                    Quantity = Math.Round(x.Minutes / 60m, 2),
                    Rate = Math.Round(rate, 2),
                    Amount = Math.Round((x.Minutes / 60m) * rate, 2),
                    CostElement = "Labor"
                };
            })
            .Where(x => x.Amount > 0m)
            .ToList();

        var postedTimesheetIdSet = postedTimesheets.Keys.ToHashSet();
        var expenseCosts = repository.Query<TimesheetExpense>(tenantContext.TenantId)
            .Where(x => postedTimesheetIdSet.Contains(x.TimesheetId))
            .Where(x => x.ExpenseDate >= request.PeriodStart && x.ExpenseDate <= request.PeriodEnd)
            .Where(x => x.Status == ExpenseStatus.Approved)
            .Where(x => x.CostType != CostType.Unallowable && x.AccountingCategory != ExpenseAccountingCategory.Unallowable)
            .ToList()
            .Select(x => new
            {
                LineId = x.Id,
                x.ChargeCodeId,
                x.CostType,
                Quantity = 1m,
                Rate = Math.Round(x.Amount, 2),
                Amount = Math.Round(x.Amount, 2),
                CostElement = "Expense"
            })
            .Where(x => x.Amount > 0m)
            .ToList();

        var burdenCosts = repository.Query<AppliedBurdenEntry>(tenantContext.TenantId)
            .Where(x => x.PostedAtUtc.HasValue)
            .Where(x => x.PeriodStart == request.PeriodStart && x.PeriodEnd == request.PeriodEnd)
            .ToList()
            .Select(x => new
            {
                LineId = x.Id,
                x.ChargeCodeId,
                CostType = CostType.Indirect,
                Quantity = Math.Round(x.BaseAmount, 2),
                Rate = x.BaseAmount == 0m ? 0m : Math.Round(x.BurdenAmount / x.BaseAmount, 4),
                Amount = Math.Round(x.BurdenAmount, 2),
                CostElement = "Burden"
            })
            .Where(x => x.Amount > 0m)
            .ToList();

        var allCosts = laborCosts
            .Select(x => new CostCandidate(x.LineId, "TimesheetLine", x.ChargeCodeId, x.CostType, x.CostElement, x.Quantity, x.Rate, x.Amount))
            .Concat(expenseCosts.Select(x => new CostCandidate(x.LineId, "TimesheetExpense", x.ChargeCodeId, x.CostType, x.CostElement, x.Quantity, x.Rate, x.Amount)))
            .Concat(burdenCosts.Select(x => new CostCandidate(x.LineId, "AppliedBurdenEntry", x.ChargeCodeId, x.CostType, x.CostElement, x.Quantity, x.Rate, x.Amount)))
            .Where(x => chargeHierarchy.ContainsKey(x.ChargeCodeId))
            .ToList();

        if (allCosts.Count == 0)
        {
            throw new DomainRuleException("No allowable posted costs found for the selected period.");
        }

        transaction.Execute(() =>
        {
            repository.Add(run);

            foreach (var contract in contracts)
            {
                var contractLines = allCosts
                    .Where(x => chargeHierarchy[x.ChargeCodeId].ContractId == contract.Id)
                    .ToList();
                if (contractLines.Count == 0)
                {
                    continue;
                }

                var projectedAmount = Math.Round(contractLines.Sum(x => x.Amount), 2);
                EnforceBillingLimit(contract, projectedAmount);

                var invoice = new Invoice
                {
                    TenantId = tenantContext.TenantId,
                    BillingRunId = run.Id,
                    ContractId = contract.Id,
                    InvoiceNumber = BuildInvoiceNumber(contract),
                    PeriodStart = request.PeriodStart,
                    PeriodEnd = request.PeriodEnd,
                    Status = InvoiceStatus.Draft,
                    CreatedAtUtc = clock.UtcNow,
                    TotalAmount = 0m
                };
                repository.Add(invoice);

                var invoiceTotal = 0m;
                var grouped = contractLines
                    .GroupBy(x => new { x.ChargeCodeId, x.CostType, x.CostElement })
                    .ToList();
                foreach (var group in grouped)
                {
                    var hierarchy = chargeHierarchy[group.Key.ChargeCodeId];
                    var quantity = Math.Round(group.Sum(x => x.Quantity), 2);
                    var amount = Math.Round(group.Sum(x => x.Amount), 2);
                    var rate = quantity == 0m ? 0m : Math.Round(amount / quantity, 4);
                    if (amount == 0m)
                    {
                        continue;
                    }

                    var line = new InvoiceLine
                    {
                        TenantId = tenantContext.TenantId,
                        InvoiceId = invoice.Id,
                        ContractId = hierarchy.ContractId,
                        TaskOrderId = hierarchy.TaskOrderId,
                        ClinId = hierarchy.ClinId,
                        WbsNodeId = hierarchy.WbsNodeId,
                        ChargeCodeId = group.Key.ChargeCodeId,
                        CostType = group.Key.CostType,
                        CostElement = group.Key.CostElement,
                        Quantity = quantity,
                        Rate = rate,
                        Amount = amount,
                        IsAllowable = true,
                        Description = $"{group.Key.CostElement} - ChargeCode {hierarchy.ChargeCode}"
                    };
                    repository.Add(line);
                    invoiceTotal += amount;

                    foreach (var source in group)
                    {
                        repository.Add(new BilledCostLink
                        {
                            TenantId = tenantContext.TenantId,
                            InvoiceLineId = line.Id,
                            SourceEntityType = source.SourceEntityType,
                            SourceEntityId = source.SourceEntityId,
                            Amount = source.Amount
                        });
                    }
                }

                invoice.TotalAmount = Math.Round(invoiceTotal, 2);
                repository.Update(invoice);
            }

            RecordAudit("BillingRun", run.Id, EventType.Create, null, run, "Generated billing run.");
        });

        var runTotal = repository.Query<Invoice>(tenantContext.TenantId)
            .Where(x => x.BillingRunId == run.Id)
            .Sum(x => x.TotalAmount);
        if (RequiresManagerBillingApproval(runTotal))
        {
            notifications.SendToRole(
                "Manager",
                "Billing Run Pending Manager Approval",
                $"Billing run {run.Id} total {Math.Round(runTotal, 2)} meets manager-approval threshold.",
                "Accounting");
            RecordAudit("BillingRun", run.Id, EventType.Submit, null, new { run.Id, runTotal }, "Submitted billing run for manager approval due to threshold.");
        }

        return run;
    }

    public BillingRun ApproveBillingRun(ApproveBillingRunRequest request)
    {
        var reason = NormalizeReason(request.Reason, "Approval reason is required.");
        var run = repository.Query<BillingRun>(tenantContext.TenantId).SingleOrDefault(x => x.Id == request.BillingRunId)
            ?? throw new DomainRuleException("Billing run not found.");
        if (run.Status != BillingRunStatus.Draft)
        {
            throw new DomainRuleException("Only draft billing runs can be approved.");
        }

        var invoices = repository.Query<Invoice>(tenantContext.TenantId).Where(x => x.BillingRunId == run.Id).ToList();
        if (invoices.Count == 0)
        {
            throw new DomainRuleException("Billing run has no invoices to approve.");
        }
        var runTotal = Math.Round(invoices.Sum(x => x.TotalAmount), 2);
        EnsureCanApproveBillingRun(runTotal);

        var before = JsonSerializer.Serialize(run);
        transaction.Execute(() =>
        {
            run.Status = BillingRunStatus.Approved;
            run.ApprovedByUserId = tenantContext.UserId;
            run.ApprovedAtUtc = clock.UtcNow;
            repository.Update(run);
            foreach (var invoice in invoices)
            {
                invoice.Status = InvoiceStatus.Approved;
                repository.Update(invoice);
            }

            RecordAudit("BillingRun", run.Id, EventType.Approve, before, run, reason);
        });

        return run;
    }

    public BillingRun PostBillingRun(PostBillingRunRequest request)
    {
        EnsureAccountant();
        var reason = NormalizeReason(request.Reason, "Posting reason is required.");
        var run = repository.Query<BillingRun>(tenantContext.TenantId).SingleOrDefault(x => x.Id == request.BillingRunId)
            ?? throw new DomainRuleException("Billing run not found.");
        if (run.Status != BillingRunStatus.Approved)
        {
            throw new DomainRuleException("Only approved billing runs can be posted.");
        }

        EnsurePostingDateOpen(run.PeriodEnd);
        EnsureBillingAccounts();
        var arAccount = repository.Query<ChartOfAccount>(tenantContext.TenantId).Single(x => x.AccountNumber == "1200");
        var revenueAccount = repository.Query<ChartOfAccount>(tenantContext.TenantId).Single(x => x.AccountNumber == "4100");

        var invoices = repository.Query<Invoice>(tenantContext.TenantId).Where(x => x.BillingRunId == run.Id).ToList();
        if (invoices.Count == 0)
        {
            throw new DomainRuleException("Billing run has no invoices to post.");
        }

        transaction.Execute(() =>
        {
            foreach (var invoice in invoices)
            {
                if (invoice.Status != InvoiceStatus.Approved)
                {
                    throw new DomainRuleException("All invoices must be approved before posting.");
                }

                var je = new JournalEntry
                {
                    TenantId = tenantContext.TenantId,
                    EntryDate = run.PeriodEnd,
                    Description = $"Billing invoice posting: {invoice.InvoiceNumber}",
                    EntryType = JournalEntryType.Billing,
                    Status = JournalEntryStatus.Posted,
                    PostedAtUtc = clock.UtcNow,
                    IsReversal = false,
                    RequestedByUserId = tenantContext.UserId,
                    ApprovedByUserId = tenantContext.UserId,
                    ApprovedAtUtc = clock.UtcNow,
                    SubmittedAtUtc = clock.UtcNow,
                    Reason = reason
                };
                repository.Add(je);
                repository.Add(new JournalLine
                {
                    TenantId = tenantContext.TenantId,
                    JournalEntryId = je.Id,
                    AccountId = arAccount.Id,
                    Debit = Math.Round(invoice.TotalAmount, 2),
                    Credit = 0m
                });
                repository.Add(new JournalLine
                {
                    TenantId = tenantContext.TenantId,
                    JournalEntryId = je.Id,
                    AccountId = revenueAccount.Id,
                    Debit = 0m,
                    Credit = Math.Round(invoice.TotalAmount, 2)
                });

                invoice.Status = InvoiceStatus.Posted;
                invoice.PostedJournalEntryId = je.Id;
                repository.Update(invoice);
            }

            var before = JsonSerializer.Serialize(run);
            run.Status = BillingRunStatus.Posted;
            run.PostedByUserId = tenantContext.UserId;
            run.PostedAtUtc = clock.UtcNow;
            repository.Update(run);
            RecordAudit("BillingRun", run.Id, EventType.Post, before, run, reason);
        });

        return run;
    }

    public IReadOnlyList<BillingReconciliationRow> BilledToBookedReconciliation(DateOnly periodStart, DateOnly periodEnd, Guid? contractId = null)
    {
        EnsureManagerOrAccountant();
        if (periodEnd < periodStart)
        {
            throw new DomainRuleException("Reconciliation period end must be on or after start.");
        }

        var contracts = repository.Query<Contract>(tenantContext.TenantId).AsQueryable();
        if (contractId.HasValue)
        {
            contracts = contracts.Where(x => x.Id == contractId.Value);
        }

        var contractList = contracts.ToList();
        if (contractList.Count == 0)
        {
            return [];
        }

        var chargeHierarchy = BuildChargeHierarchy();
        var ratesByUser = repository.Query<PersonnelProfile>(tenantContext.TenantId).ToDictionary(x => x.UserId, x => x.HourlyRate);

        var postedSheets = repository.Query<Timesheet>(tenantContext.TenantId)
            .Where(x => x.PostedAtUtc.HasValue && x.PeriodStart <= periodEnd && x.PeriodEnd >= periodStart)
            .ToDictionary(x => x.Id);
        var postedSheetIds = postedSheets.Keys.ToList();
        var bookedLaborByContract = repository.Query<TimesheetLine>(tenantContext.TenantId)
            .Where(x => postedSheetIds.Contains(x.TimesheetId))
            .ToList()
            .Where(x => x.WorkDate >= periodStart && x.WorkDate <= periodEnd)
            .Where(x => x.CostType != CostType.Unallowable)
            .Where(x => chargeHierarchy.ContainsKey(x.ChargeCodeId))
            .GroupBy(x => chargeHierarchy[x.ChargeCodeId].ContractId)
            .ToDictionary(
                x => x.Key,
                x => Math.Round(x.Sum(line =>
                {
                    var sheet = postedSheets[line.TimesheetId];
                    var rate = ratesByUser.TryGetValue(sheet.UserId, out var hourly) ? hourly : 0m;
                    return (line.Minutes / 60m) * rate;
                }), 2));

        var postedSheetIdSet = postedSheets.Keys.ToHashSet();
        var bookedExpenseByContract = repository.Query<TimesheetExpense>(tenantContext.TenantId)
            .Where(x => postedSheetIdSet.Contains(x.TimesheetId))
            .Where(x => x.ExpenseDate >= periodStart && x.ExpenseDate <= periodEnd)
            .Where(x => x.Status == ExpenseStatus.Approved)
            .Where(x => x.CostType != CostType.Unallowable && x.AccountingCategory != ExpenseAccountingCategory.Unallowable)
            .ToList()
            .Where(x => chargeHierarchy.ContainsKey(x.ChargeCodeId))
            .GroupBy(x => chargeHierarchy[x.ChargeCodeId].ContractId)
            .ToDictionary(x => x.Key, x => Math.Round(x.Sum(v => v.Amount), 2));

        var bookedBurdenByContract = repository.Query<AppliedBurdenEntry>(tenantContext.TenantId)
            .Where(x => x.PeriodStart == periodStart && x.PeriodEnd == periodEnd && x.PostedAtUtc.HasValue)
            .ToList()
            .GroupBy(x => x.ContractId)
            .ToDictionary(x => x.Key, x => Math.Round(x.Sum(v => v.BurdenAmount), 2));

        var billedByContract = repository.Query<Invoice>(tenantContext.TenantId)
            .Where(x => x.Status == InvoiceStatus.Posted)
            .Where(x => x.PeriodStart <= periodEnd && x.PeriodEnd >= periodStart)
            .ToList()
            .GroupBy(x => x.ContractId)
            .ToDictionary(x => x.Key, x => Math.Round(x.Sum(v => v.TotalAmount), 2));

        var billedToDateByContract = repository.Query<Invoice>(tenantContext.TenantId)
            .Where(x => x.Status == InvoiceStatus.Posted)
            .ToList()
            .GroupBy(x => x.ContractId)
            .ToDictionary(x => x.Key, x => Math.Round(x.Sum(v => v.TotalAmount), 2));

        return contractList.Select(contract =>
        {
            var booked = (bookedLaborByContract.TryGetValue(contract.Id, out var labor) ? labor : 0m)
                + (bookedExpenseByContract.TryGetValue(contract.Id, out var expense) ? expense : 0m)
                + (bookedBurdenByContract.TryGetValue(contract.Id, out var burden) ? burden : 0m);
            var billed = billedByContract.TryGetValue(contract.Id, out var currentBilled) ? currentBilled : 0m;
            var variance = Math.Round(billed - booked, 2);
            var (limit, billedToDate) = CurrentLimitAndBilledToDate(contract);

            return new BillingReconciliationRow(
                contract.Id,
                contract.ContractNumber,
                periodStart,
                periodEnd,
                Math.Round(booked, 2),
                Math.Round(billed, 2),
                variance,
                Math.Abs(variance) < 0.01m ? "Matched" : "Variance",
                limit,
                billedToDateByContract.TryGetValue(contract.Id, out var totalBilledToDate) ? totalBilledToDate : billedToDate);
        })
        .OrderBy(x => x.ContractNumber)
        .ToList();
    }

    private void EnforceBillingLimit(Contract contract, decimal projectedAmount)
    {
        var (limit, billedToDate) = CurrentLimitAndBilledToDate(contract);
        if (limit.HasValue && billedToDate + projectedAmount > limit.Value)
        {
            throw new DomainRuleException($"Billing would exceed limit for contract {contract.ContractNumber}. Limit={limit.Value}, billedToDate={billedToDate}, projected={projectedAmount}.");
        }
    }

    private (decimal? Limit, decimal BilledToDate) CurrentLimitAndBilledToDate(Contract contract)
    {
        var ceiling = repository.Query<BillingCeiling>(tenantContext.TenantId)
            .SingleOrDefault(x => x.ContractId == contract.Id && x.IsActive);
        decimal? limit = null;
        if (ceiling is not null)
        {
            var ceilingLimit = Math.Round(ceiling.CeilingAmount, 2);
            var fundedLimit = Math.Round(ceiling.FundedAmount, 2);
            limit = Math.Min(ceilingLimit, fundedLimit);
        }
        else if (contract.BudgetAmount > 0m)
        {
            limit = Math.Round(contract.BudgetAmount, 2);
        }

        var billedToDate = Math.Round(repository.Query<Invoice>(tenantContext.TenantId)
            .Where(x => x.ContractId == contract.Id && (x.Status == InvoiceStatus.Approved || x.Status == InvoiceStatus.Posted))
            .Sum(x => x.TotalAmount), 2);
        return (limit, billedToDate);
    }

    private Dictionary<Guid, ChargeHierarchy> BuildChargeHierarchy()
    {
        var contracts = repository.Query<Contract>(tenantContext.TenantId).ToDictionary(x => x.Id);
        var taskOrders = repository.Query<TaskOrder>(tenantContext.TenantId).ToDictionary(x => x.Id);
        var clins = repository.Query<Clin>(tenantContext.TenantId).ToDictionary(x => x.Id);
        var wbs = repository.Query<WbsNode>(tenantContext.TenantId).ToDictionary(x => x.Id);
        return repository.Query<ChargeCode>(tenantContext.TenantId).ToList()
            .Where(x => wbs.ContainsKey(x.WbsNodeId))
            .Select(x =>
            {
                var wbsNode = wbs[x.WbsNodeId];
                if (!clins.TryGetValue(wbsNode.ClinId, out var clin))
                {
                    return null;
                }

                if (!taskOrders.TryGetValue(clin.TaskOrderId, out var taskOrder))
                {
                    return null;
                }

                if (!contracts.ContainsKey(taskOrder.ContractId))
                {
                    return null;
                }

                return new
                {
                    ChargeCodeId = x.Id,
                    Hierarchy = new ChargeHierarchy(taskOrder.ContractId, taskOrder.Id, clin.Id, wbsNode.Id, x.Code)
                };
            })
            .Where(x => x is not null)
            .ToDictionary(x => x!.ChargeCodeId, x => x!.Hierarchy);
    }

    private void EnsurePostingDateOpen(DateOnly entryDate)
    {
        var period = repository.Query<AccountingPeriod>(tenantContext.TenantId)
            .SingleOrDefault(x => entryDate >= x.StartDate && entryDate <= x.EndDate);
        if (period is not null && period.Status == AccountingPeriodStatus.Closed)
        {
            throw new DomainRuleException("Cannot post billing into a closed accounting period.");
        }
    }

    private void EnsureBillingAccounts()
    {
        var existingNumbers = repository.Query<ChartOfAccount>(tenantContext.TenantId)
            .Select(x => x.AccountNumber)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (!existingNumbers.Contains("1200"))
        {
            repository.Add(new ChartOfAccount
            {
                TenantId = tenantContext.TenantId,
                AccountNumber = "1200",
                Name = "Accounts Receivable",
                CostType = CostType.Direct
            });
        }

        if (!existingNumbers.Contains("4100"))
        {
            repository.Add(new ChartOfAccount
            {
                TenantId = tenantContext.TenantId,
                AccountNumber = "4100",
                Name = "Contract Billings Revenue",
                CostType = CostType.Direct
            });
        }
    }

    private static string BuildInvoiceNumber(Contract contract)
    {
        var suffix = Guid.NewGuid().ToString("N")[..6].ToUpperInvariant();
        return $"{contract.ContractNumber}-{DateTime.UtcNow:yyyyMMdd}-{suffix}";
    }

    private static string NormalizeReason(string? reason, string message)
    {
        var value = reason?.Trim();
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new DomainRuleException(message);
        }

        return value;
    }

    private void EnsureAccountant()
    {
        if (!tenantContext.Roles.Contains("Accountant", StringComparer.OrdinalIgnoreCase))
        {
            throw new DomainRuleException("Only accountants can manage billing.");
        }
    }

    private void EnsureManager()
    {
        if (!tenantContext.Roles.Contains("Manager", StringComparer.OrdinalIgnoreCase))
        {
            throw new DomainRuleException("Only managers can approve billing runs.");
        }
    }

    private void EnsureCanApproveBillingRun(decimal runTotal)
    {
        var requiresManager = RequiresManagerBillingApproval(runTotal);
        if (requiresManager)
        {
            EnsureManager();
            return;
        }

        EnsureManagerOrAccountant();
    }

    private bool RequiresManagerBillingApproval(decimal runTotal)
    {
        var policy = repository.Query<ManagementReviewPolicy>(tenantContext.TenantId).SingleOrDefault();
        if (policy is null)
        {
            return false;
        }

        if (!policy.RequireManagerApprovalForBillingAboveThreshold)
        {
            return false;
        }

        var threshold = Math.Max(0m, policy.BillingManagerApprovalThreshold);
        return threshold > 0m && runTotal >= threshold;
    }

    private void EnsureManagerOrAccountant()
    {
        if (tenantContext.Roles.Contains("Accountant", StringComparer.OrdinalIgnoreCase) ||
            tenantContext.Roles.Contains("Manager", StringComparer.OrdinalIgnoreCase))
        {
            return;
        }

        throw new DomainRuleException("Only managers or accountants can view billing workflows.");
    }

    private void RecordAudit(string entityType, Guid entityId, EventType eventType, object? before, object? after, string? reason)
    {
        audit.Record(new AuditEvent
        {
            TenantId = tenantContext.TenantId,
            EntityType = entityType,
            EntityId = entityId,
            EventType = eventType,
            ActorUserId = tenantContext.UserId,
            ActorRoles = string.Join(',', tenantContext.Roles),
            OccurredAtUtc = clock.UtcNow,
            ReasonForChange = reason,
            BeforeJson = before is null ? null : JsonSerializer.Serialize(before),
            AfterJson = after is null ? null : JsonSerializer.Serialize(after),
            CorrelationId = correlation.CorrelationId
        });
    }

    private sealed record CostCandidate(
        Guid SourceEntityId,
        string SourceEntityType,
        Guid ChargeCodeId,
        CostType CostType,
        string CostElement,
        decimal Quantity,
        decimal Rate,
        decimal Amount);

    private sealed record ChargeHierarchy(
        Guid ContractId,
        Guid TaskOrderId,
        Guid ClinId,
        Guid WbsNodeId,
        string ChargeCode);
}
