using GovConMoney.Application.Abstractions;
using GovConMoney.Application.Models;
using GovConMoney.Domain.Entities;
using GovConMoney.Domain.Enums;
using System.Text.Json;

namespace GovConMoney.Application.Services;

public sealed class IndirectRateService(
    IRepository repository,
    ITenantContext tenantContext,
    IAuditService audit,
    ICorrelationContext correlation,
    IClock clock,
    IAppTransaction transaction,
    AccountingService accounting)
{
    public IReadOnlyList<RateCalculation> ComputeRates(ComputeIndirectRatesRequest request)
    {
        if (request.PeriodEnd < request.PeriodStart)
        {
            throw new DomainRuleException("Indirect rate period end must be on or after period start.");
        }

        var pools = repository.Query<IndirectPool>(tenantContext.TenantId)
            .Where(x => x.IsActive)
            .Where(x => request.PeriodStart <= x.EffectiveEndDate && request.PeriodEnd >= x.EffectiveStartDate)
            .ToList();
        if (pools.Count == 0)
        {
            throw new DomainRuleException("No active indirect pools configured for the selected period.");
        }

        var lines = GetPostedLinesInPeriod(request.PeriodStart, request.PeriodEnd);
        var expenses = GetPostedExpensesInPeriod(request.PeriodStart, request.PeriodEnd);

        var results = new List<RateCalculation>();
        transaction.Execute(() =>
        {
            foreach (var pool in pools)
            {
                var allocationBase = ResolveActiveAllocationBase(pool.Id);
                var poolCost = CalculateLaborCost(lines.Where(x => x.Line.CostType == pool.PoolCostType).ToList())
                    + CalculateExpenseCost(expenses.Where(x => x.CostType == pool.PoolCostType).ToList(), pool.ExcludeUnallowable);
                var baseRows = ResolveBaseRows(lines, allocationBase);
                var baseTotal = CalculateBaseTotal(baseRows, allocationBase.BaseMethod);
                if (baseTotal <= 0m)
                {
                    throw new DomainRuleException($"Allocation base total is zero for pool {pool.Name}.");
                }

                var existingVersions = repository.Query<RateCalculation>(tenantContext.TenantId)
                    .Where(x => x.IndirectPoolId == pool.Id && x.PeriodStart == request.PeriodStart && x.PeriodEnd == request.PeriodEnd)
                    .Select(x => x.Version)
                    .ToList();
                var version = (existingVersions.Count == 0 ? 0 : existingVersions.Max()) + 1;

                var rate = Math.Round(poolCost / baseTotal, 8);
                var calc = new RateCalculation
                {
                    TenantId = tenantContext.TenantId,
                    IndirectPoolId = pool.Id,
                    PeriodStart = request.PeriodStart,
                    PeriodEnd = request.PeriodEnd,
                    PoolCost = Math.Round(poolCost, 2),
                    AllocationBaseTotal = Math.Round(baseTotal, 2),
                    Rate = rate,
                    Version = version,
                    IsFinal = request.IsFinal,
                    CalculatedAtUtc = clock.UtcNow,
                    CalculatedByUserId = tenantContext.UserId,
                    ReviewStatus = request.IsFinal ? RateCalculationReviewStatus.PendingManagerApproval : RateCalculationReviewStatus.NotRequired,
                    SubmittedForReviewByUserId = request.IsFinal ? tenantContext.UserId : null,
                    SubmittedForReviewAtUtc = request.IsFinal ? clock.UtcNow : null
                };
                repository.Add(calc);
                results.Add(calc);

                RecordAudit("RateCalculation", calc.Id, EventType.Create, null, calc, $"Computed indirect rate for pool {pool.Name}.");
                if (request.IsFinal)
                {
                    RecordAudit("RateCalculation", calc.Id, EventType.Submit, null, new { calc.Id, calc.ReviewStatus }, "Submitted final indirect rate for manager approval.");
                }
            }
        });

        return results;
    }

    public IReadOnlyList<AppliedBurdenEntry> ApplyBurden(ApplyIndirectBurdenRequest request)
    {
        if (request.PeriodEnd < request.PeriodStart)
        {
            throw new DomainRuleException("Burden application period end must be on or after period start.");
        }

        var rateCalcs = ResolveRateCalculations(request.PeriodStart, request.PeriodEnd, request.IndirectPoolId, request.RateCalculationId);
        var entries = new List<AppliedBurdenEntry>();
        var periodLines = GetPostedLinesInPeriod(request.PeriodStart, request.PeriodEnd);

        transaction.Execute(() =>
        {
            foreach (var calc in rateCalcs)
            {
                EnsureFinalRateApproved(calc);
                var pool = repository.Query<IndirectPool>(tenantContext.TenantId).Single(x => x.Id == calc.IndirectPoolId);
                var allocationBase = ResolveActiveAllocationBase(pool.Id);
                var targetLines = ResolveBaseRows(periodLines, allocationBase);

                foreach (var target in targetLines)
                {
                    var lineBaseAmount = CalculateBaseAmountForLine(target, allocationBase.BaseMethod);
                    if (lineBaseAmount == 0m)
                    {
                        continue;
                    }

                    var burdenAmount = Math.Round(lineBaseAmount * calc.Rate, 2);
                    if (burdenAmount == 0m)
                    {
                        continue;
                    }

                    var hierarchy = ResolveHierarchy(target.Line.ChargeCodeId);
                    var burden = new AppliedBurdenEntry
                    {
                        TenantId = tenantContext.TenantId,
                        TimesheetLineId = target.Line.Id,
                        IndirectPoolId = pool.Id,
                        RateCalculationId = calc.Id,
                        PeriodStart = request.PeriodStart,
                        PeriodEnd = request.PeriodEnd,
                        ContractId = hierarchy.ContractId,
                        TaskOrderId = hierarchy.TaskOrderId,
                        ClinId = hierarchy.ClinId,
                        WbsNodeId = hierarchy.WbsNodeId,
                        ChargeCodeId = target.Line.ChargeCodeId,
                        BaseAmount = lineBaseAmount,
                        BurdenAmount = burdenAmount,
                        IsAdjustment = false,
                        AppliedAtUtc = clock.UtcNow
                    };
                    repository.Add(burden);
                    entries.Add(burden);
                }

                if (entries.Count > 0)
                {
                    RecordAudit("RateCalculation", calc.Id, EventType.Post, null, new { calc.Id, EntryCount = entries.Count }, "Applied burdens using indirect rate calculation.");
                }
            }
        });

        if (request.PostToGeneralLedger && entries.Count > 0)
        {
            accounting.PostAppliedBurdenEntries(entries.Select(x => x.Id).ToList());
        }

        return entries;
    }

    public IReadOnlyList<AppliedBurdenEntry> Rerate(RerateIndirectBurdenRequest request)
    {
        if (request.PeriodEnd < request.PeriodStart)
        {
            throw new DomainRuleException("Rerate period end must be on or after period start.");
        }

        var pool = repository.Query<IndirectPool>(tenantContext.TenantId).SingleOrDefault(x => x.Id == request.IndirectPoolId && x.IsActive)
            ?? throw new DomainRuleException("Indirect pool not found.");
        var versions = repository.Query<RateCalculation>(tenantContext.TenantId)
            .Where(x => x.IndirectPoolId == pool.Id && x.PeriodStart == request.PeriodStart && x.PeriodEnd == request.PeriodEnd)
            .Select(x => x.Version)
            .ToList();
        var nextVersion = (versions.Count == 0 ? 0 : versions.Max()) + 1;
        var calc = new RateCalculation
        {
            TenantId = tenantContext.TenantId,
            IndirectPoolId = pool.Id,
            PeriodStart = request.PeriodStart,
            PeriodEnd = request.PeriodEnd,
            PoolCost = 0m,
            AllocationBaseTotal = 0m,
            Rate = request.NewRate,
            Version = nextVersion,
            IsFinal = request.IsFinal,
            CalculatedAtUtc = clock.UtcNow,
            CalculatedByUserId = tenantContext.UserId,
            ReviewStatus = request.IsFinal ? RateCalculationReviewStatus.PendingManagerApproval : RateCalculationReviewStatus.NotRequired,
            SubmittedForReviewByUserId = request.IsFinal ? tenantContext.UserId : null,
            SubmittedForReviewAtUtc = request.IsFinal ? clock.UtcNow : null
        };

        var adjustments = new List<AppliedBurdenEntry>();
        var periodLines = GetPostedLinesInPeriod(request.PeriodStart, request.PeriodEnd);
        transaction.Execute(() =>
        {
            repository.Add(calc);
            var allocationBase = ResolveActiveAllocationBase(pool.Id);
            var targetLines = ResolveBaseRows(periodLines, allocationBase);
            var existing = repository.Query<AppliedBurdenEntry>(tenantContext.TenantId)
                .Where(x => x.IndirectPoolId == pool.Id && x.PeriodStart == request.PeriodStart && x.PeriodEnd == request.PeriodEnd)
                .ToList()
                .GroupBy(x => x.TimesheetLineId)
                .ToDictionary(x => x.Key, x => Math.Round(x.Sum(v => v.BurdenAmount), 2));

            foreach (var target in targetLines)
            {
                var lineBaseAmount = CalculateBaseAmountForLine(target, allocationBase.BaseMethod);
                var desired = Math.Round(lineBaseAmount * request.NewRate, 2);
                var current = existing.TryGetValue(target.Line.Id, out var prior) ? prior : 0m;
                var delta = Math.Round(desired - current, 2);
                if (delta == 0m)
                {
                    continue;
                }

                var hierarchy = ResolveHierarchy(target.Line.ChargeCodeId);
                var adjustment = new AppliedBurdenEntry
                {
                    TenantId = tenantContext.TenantId,
                    TimesheetLineId = target.Line.Id,
                    IndirectPoolId = pool.Id,
                    RateCalculationId = calc.Id,
                    PeriodStart = request.PeriodStart,
                    PeriodEnd = request.PeriodEnd,
                    ContractId = hierarchy.ContractId,
                    TaskOrderId = hierarchy.TaskOrderId,
                    ClinId = hierarchy.ClinId,
                    WbsNodeId = hierarchy.WbsNodeId,
                    ChargeCodeId = target.Line.ChargeCodeId,
                    BaseAmount = lineBaseAmount,
                    BurdenAmount = delta,
                    IsAdjustment = true,
                    AppliedAtUtc = clock.UtcNow
                };
                repository.Add(adjustment);
                adjustments.Add(adjustment);
            }

            RecordAudit("RateCalculation", calc.Id, EventType.Reverse, null, new { calc.Id, DeltaCount = adjustments.Count, request.NewRate }, "Rerated indirect burden and generated delta entries.");
            if (request.IsFinal)
            {
                RecordAudit("RateCalculation", calc.Id, EventType.Submit, null, new { calc.Id, calc.ReviewStatus }, "Submitted rerated final indirect rate for manager approval.");
            }
        });

        if (request.PostToGeneralLedger && adjustments.Count > 0)
        {
            accounting.PostAppliedBurdenEntries(adjustments.Select(x => x.Id).ToList());
        }

        return adjustments;
    }

    public IReadOnlyList<IndirectRateSupportRow> RateSupport(DateOnly? periodStart, DateOnly? periodEnd)
    {
        var poolById = repository.Query<IndirectPool>(tenantContext.TenantId).ToDictionary(x => x.Id, x => x.Name);
        var query = repository.Query<RateCalculation>(tenantContext.TenantId).AsQueryable();
        if (periodStart.HasValue)
        {
            query = query.Where(x => x.PeriodEnd >= periodStart.Value);
        }

        if (periodEnd.HasValue)
        {
            query = query.Where(x => x.PeriodStart <= periodEnd.Value);
        }

        return query
            .OrderByDescending(x => x.PeriodEnd)
            .ThenByDescending(x => x.Version)
            .ToList()
            .Select(x => new IndirectRateSupportRow(
                x.IndirectPoolId,
                poolById.TryGetValue(x.IndirectPoolId, out var name) ? name : "(unknown)",
                x.Id,
                x.PeriodStart,
                x.PeriodEnd,
                x.PoolCost,
                x.AllocationBaseTotal,
                x.Rate,
                x.Version,
                x.IsFinal,
                x.CalculatedAtUtc,
                x.ReviewStatus,
                x.SubmittedForReviewByUserId,
                x.SubmittedForReviewAtUtc,
                x.ReviewedByUserId,
                x.ReviewedAtUtc,
                x.ReviewNote))
            .ToList();
    }

    public RateCalculation SubmitFinalForManagerReview(Guid rateCalculationId, string? reason)
    {
        EnsureAccountantRole();
        var calc = repository.Query<RateCalculation>(tenantContext.TenantId).SingleOrDefault(x => x.Id == rateCalculationId)
            ?? throw new DomainRuleException("Rate calculation not found.");
        if (!calc.IsFinal)
        {
            throw new DomainRuleException("Only final rate calculations can be submitted for manager review.");
        }

        var before = new { calc.IsFinal, calc.ReviewStatus, calc.SubmittedForReviewByUserId, calc.SubmittedForReviewAtUtc, calc.ReviewNote };
        calc.ReviewStatus = RateCalculationReviewStatus.PendingManagerApproval;
        calc.SubmittedForReviewByUserId = tenantContext.UserId;
        calc.SubmittedForReviewAtUtc = clock.UtcNow;
        calc.ReviewedByUserId = null;
        calc.ReviewedAtUtc = null;
        calc.ReviewNote = reason;

        repository.Update(calc);
        RecordAudit("RateCalculation", calc.Id, EventType.Submit, before, calc, string.IsNullOrWhiteSpace(reason) ? "Submitted indirect rate for manager approval." : reason);
        return calc;
    }

    public RateCalculation ApproveFinalRate(Guid rateCalculationId, string reason)
    {
        EnsureManagerRole();
        if (string.IsNullOrWhiteSpace(reason))
        {
            throw new DomainRuleException("Approval reason is required.");
        }

        var calc = repository.Query<RateCalculation>(tenantContext.TenantId).SingleOrDefault(x => x.Id == rateCalculationId)
            ?? throw new DomainRuleException("Rate calculation not found.");
        if (!calc.IsFinal)
        {
            throw new DomainRuleException("Only final rate calculations require manager approval.");
        }

        var before = new { calc.ReviewStatus, calc.ReviewedByUserId, calc.ReviewedAtUtc, calc.ReviewNote };
        calc.ReviewStatus = RateCalculationReviewStatus.Approved;
        calc.ReviewedByUserId = tenantContext.UserId;
        calc.ReviewedAtUtc = clock.UtcNow;
        calc.ReviewNote = reason;
        repository.Update(calc);
        RecordAudit("RateCalculation", calc.Id, EventType.Approve, before, calc, reason);
        return calc;
    }

    public RateCalculation RejectFinalRate(Guid rateCalculationId, string reason)
    {
        EnsureManagerRole();
        if (string.IsNullOrWhiteSpace(reason))
        {
            throw new DomainRuleException("Rejection reason is required.");
        }

        var calc = repository.Query<RateCalculation>(tenantContext.TenantId).SingleOrDefault(x => x.Id == rateCalculationId)
            ?? throw new DomainRuleException("Rate calculation not found.");
        if (!calc.IsFinal)
        {
            throw new DomainRuleException("Only final rate calculations require manager review.");
        }

        var before = new { calc.ReviewStatus, calc.ReviewedByUserId, calc.ReviewedAtUtc, calc.ReviewNote };
        calc.ReviewStatus = RateCalculationReviewStatus.Rejected;
        calc.ReviewedByUserId = tenantContext.UserId;
        calc.ReviewedAtUtc = clock.UtcNow;
        calc.ReviewNote = reason;
        repository.Update(calc);
        RecordAudit("RateCalculation", calc.Id, EventType.Reject, before, calc, reason);
        return calc;
    }

    public IReadOnlyList<AppliedBurdenSummaryRow> BurdenSummary(DateOnly? periodStart, DateOnly? periodEnd)
    {
        var poolById = repository.Query<IndirectPool>(tenantContext.TenantId).ToDictionary(x => x.Id, x => x.Name);
        var rateById = repository.Query<RateCalculation>(tenantContext.TenantId).ToDictionary(x => x.Id, x => x.Rate);
        var query = repository.Query<AppliedBurdenEntry>(tenantContext.TenantId).AsQueryable();
        if (periodStart.HasValue)
        {
            query = query.Where(x => x.PeriodEnd >= periodStart.Value);
        }

        if (periodEnd.HasValue)
        {
            query = query.Where(x => x.PeriodStart <= periodEnd.Value);
        }

        return query.ToList()
            .GroupBy(x => new { x.RateCalculationId, x.IndirectPoolId, x.PeriodStart, x.PeriodEnd, x.IsAdjustment })
            .Select(g => new AppliedBurdenSummaryRow(
                g.Key.RateCalculationId,
                g.Key.IndirectPoolId,
                poolById.TryGetValue(g.Key.IndirectPoolId, out var poolName) ? poolName : "(unknown)",
                g.Key.PeriodStart,
                g.Key.PeriodEnd,
                g.Count(),
                Math.Round(g.Sum(x => x.BaseAmount), 2),
                Math.Round(g.Sum(x => x.BurdenAmount), 2),
                rateById.TryGetValue(g.Key.RateCalculationId, out var rate) ? rate : 0m,
                g.Key.IsAdjustment,
                g.All(x => x.PostedAtUtc.HasValue)))
            .OrderByDescending(x => x.PeriodEnd)
            .ThenBy(x => x.PoolName)
            .ToList();
    }

    private IReadOnlyList<(TimesheetLine Line, Timesheet Sheet, decimal HourlyRate)> GetPostedLinesInPeriod(DateOnly start, DateOnly end)
    {
        var sheets = repository.Query<Timesheet>(tenantContext.TenantId)
            .Where(x => x.PostedAtUtc.HasValue)
            .Where(x => x.PeriodEnd >= start && x.PeriodStart <= end)
            .ToList();
        var sheetById = sheets.ToDictionary(x => x.Id);
        var rates = repository.Query<PersonnelProfile>(tenantContext.TenantId).ToDictionary(x => x.UserId, x => x.HourlyRate);

        return repository.Query<TimesheetLine>(tenantContext.TenantId)
            .Where(x => sheetById.ContainsKey(x.TimesheetId))
            .ToList()
            .Where(x => x.WorkDate >= start && x.WorkDate <= end)
            .Select(x =>
            {
                var sheet = sheetById[x.TimesheetId];
                var rate = rates.TryGetValue(sheet.UserId, out var hourlyRate) ? hourlyRate : 0m;
                return (x, sheet, rate);
            })
            .ToList();
    }

    private IReadOnlyList<TimesheetExpense> GetPostedExpensesInPeriod(DateOnly start, DateOnly end)
    {
        var postedSheetIds = repository.Query<Timesheet>(tenantContext.TenantId)
            .Where(x => x.PostedAtUtc.HasValue)
            .Where(x => x.PeriodEnd >= start && x.PeriodStart <= end)
            .Select(x => x.Id)
            .ToHashSet();

        return repository.Query<TimesheetExpense>(tenantContext.TenantId)
            .Where(x => postedSheetIds.Contains(x.TimesheetId))
            .Where(x => x.ExpenseDate >= start && x.ExpenseDate <= end)
            .Where(x => x.Status == ExpenseStatus.Approved)
            .ToList();
    }

    private static decimal CalculateLaborCost(IReadOnlyList<(TimesheetLine Line, Timesheet Sheet, decimal HourlyRate)> rows)
        => Math.Round(rows.Sum(x => (x.Line.Minutes / 60m) * x.HourlyRate), 2);

    private static decimal CalculateExpenseCost(IReadOnlyList<TimesheetExpense> expenses, bool excludeUnallowable)
        => Math.Round(expenses
            .Where(x => !excludeUnallowable || x.AccountingCategory != ExpenseAccountingCategory.Unallowable)
            .Sum(x => x.Amount), 2);

    private AllocationBase ResolveActiveAllocationBase(Guid poolId)
    {
        var bases = repository.Query<AllocationBase>(tenantContext.TenantId)
            .Where(x => x.IndirectPoolId == poolId && x.IsActive)
            .ToList();
        if (bases.Count == 0)
        {
            throw new DomainRuleException("No active allocation base configured for indirect pool.");
        }

        if (bases.Count > 1)
        {
            throw new DomainRuleException("Multiple active allocation bases configured for indirect pool; only one active base is allowed.");
        }

        return bases[0];
    }

    private static IReadOnlyList<(TimesheetLine Line, Timesheet Sheet, decimal HourlyRate)> ResolveBaseRows(
        IReadOnlyList<(TimesheetLine Line, Timesheet Sheet, decimal HourlyRate)> periodLines,
        AllocationBase allocationBase)
    {
        return allocationBase.BaseMethod switch
        {
            AllocationBaseMethod.PoolBaseCostTypeLaborDollars => periodLines.Where(x => x.Line.CostType == allocationBase.BaseCostType).ToList(),
            AllocationBaseMethod.DirectLaborDollars => periodLines.Where(x => x.Line.CostType == CostType.Direct).ToList(),
            AllocationBaseMethod.DirectLaborHours => periodLines.Where(x => x.Line.CostType == CostType.Direct).ToList(),
            AllocationBaseMethod.TotalLaborHours => periodLines.ToList(),
            _ => throw new DomainRuleException($"Unsupported allocation base method: {allocationBase.BaseMethod}.")
        };
    }

    private static decimal CalculateBaseTotal(
        IReadOnlyList<(TimesheetLine Line, Timesheet Sheet, decimal HourlyRate)> rows,
        AllocationBaseMethod method)
    {
        return method switch
        {
            AllocationBaseMethod.PoolBaseCostTypeLaborDollars or AllocationBaseMethod.DirectLaborDollars => CalculateLaborCost(rows),
            AllocationBaseMethod.DirectLaborHours or AllocationBaseMethod.TotalLaborHours => CalculateLaborHours(rows),
            _ => throw new DomainRuleException($"Unsupported allocation base method: {method}.")
        };
    }

    private static decimal CalculateBaseAmountForLine(
        (TimesheetLine Line, Timesheet Sheet, decimal HourlyRate) row,
        AllocationBaseMethod method)
    {
        return method switch
        {
            AllocationBaseMethod.PoolBaseCostTypeLaborDollars or AllocationBaseMethod.DirectLaborDollars =>
                Math.Round((row.Line.Minutes / 60m) * row.HourlyRate, 2),
            AllocationBaseMethod.DirectLaborHours or AllocationBaseMethod.TotalLaborHours =>
                Math.Round(row.Line.Minutes / 60m, 2),
            _ => throw new DomainRuleException($"Unsupported allocation base method: {method}.")
        };
    }

    private static decimal CalculateLaborHours(IReadOnlyList<(TimesheetLine Line, Timesheet Sheet, decimal HourlyRate)> rows)
        => Math.Round(rows.Sum(x => x.Line.Minutes / 60m), 2);

    private IReadOnlyList<RateCalculation> ResolveRateCalculations(DateOnly start, DateOnly end, Guid? poolId, Guid? rateCalculationId)
    {
        if (rateCalculationId.HasValue)
        {
            var calc = repository.Query<RateCalculation>(tenantContext.TenantId)
                .SingleOrDefault(x => x.Id == rateCalculationId.Value)
                ?? throw new DomainRuleException("Rate calculation not found.");
            return [calc];
        }

        var query = repository.Query<RateCalculation>(tenantContext.TenantId)
            .Where(x => x.PeriodStart == start && x.PeriodEnd == end);
        if (poolId.HasValue)
        {
            query = query.Where(x => x.IndirectPoolId == poolId.Value);
        }

        var candidates = query.ToList();
        var latestPerPool = candidates
            .GroupBy(x => x.IndirectPoolId)
            .Select(x => x.OrderByDescending(v => v.Version).First())
            .ToList();
        if (latestPerPool.Count == 0)
        {
            throw new DomainRuleException("No indirect rate calculations found for the selected period.");
        }

        return latestPerPool;
    }

    private void EnsureFinalRateApproved(RateCalculation calc)
    {
        if (!calc.IsFinal)
        {
            return;
        }

        if (calc.ReviewStatus != RateCalculationReviewStatus.Approved)
        {
            throw new DomainRuleException($"Final rate calculation {calc.Id} is not manager approved.");
        }
    }

    private void EnsureAccountantRole()
    {
        if (tenantContext.Roles.Contains("Accountant", StringComparer.OrdinalIgnoreCase))
        {
            return;
        }

        throw new DomainRuleException("Only accountants can submit indirect rates for manager review.");
    }

    private void EnsureManagerRole()
    {
        if (tenantContext.Roles.Contains("Manager", StringComparer.OrdinalIgnoreCase))
        {
            return;
        }

        throw new DomainRuleException("Only managers can approve or reject final indirect rates.");
    }

    private (Guid ContractId, Guid TaskOrderId, Guid ClinId, Guid WbsNodeId) ResolveHierarchy(Guid chargeCodeId)
    {
        var chargeCode = repository.Query<ChargeCode>(tenantContext.TenantId).Single(x => x.Id == chargeCodeId);
        var wbs = repository.Query<WbsNode>(tenantContext.TenantId).Single(x => x.Id == chargeCode.WbsNodeId);
        var clin = repository.Query<Clin>(tenantContext.TenantId).Single(x => x.Id == wbs.ClinId);
        var task = repository.Query<TaskOrder>(tenantContext.TenantId).Single(x => x.Id == clin.TaskOrderId);
        return (task.ContractId, task.Id, clin.Id, wbs.Id);
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
}
