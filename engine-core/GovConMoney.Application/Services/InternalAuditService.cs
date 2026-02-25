using GovConMoney.Application.Abstractions;
using GovConMoney.Application.Models;
using GovConMoney.Domain.Entities;
using GovConMoney.Domain.Enums;
using System.Text.Json;

namespace GovConMoney.Application.Services;

public sealed class InternalAuditService(
    IRepository repository,
    ITenantContext tenantContext,
    IAuditService audit,
    ICorrelationContext correlation,
    IClock clock,
    IAppTransaction transaction,
    NotificationService notifications)
{
    private static readonly (string ClauseRef, string ControlName)[] ChecklistTemplate =
    [
        ("(c)(2)", "Direct and indirect segregation review"),
        ("(c)(4)", "Indirect accumulation/allocation review"),
        ("(c)(6)", "Subledger to GL tie-out review"),
        ("(c)(7)", "Adjusting entries review"),
        ("(c)(8)", "Management review and internal audit review"),
        ("(c)(9)", "Timekeeping compliance review"),
        ("(c)(10)", "Labor distribution review"),
        ("(c)(11)", "Monthly close cadence review"),
        ("(c)(12)", "Unallowable exclusion review"),
        ("(c)(16)", "Billing reconciliation review")
    ];

    public IReadOnlyList<InternalAuditCycle> SyncCycles(DateOnly? asOfDate = null)
    {
        var policy = ResolvePolicy();
        if (!policy.EnablePeriodicInternalAuditAttestation)
        {
            return [];
        }

        var asOf = asOfDate ?? DateOnly.FromDateTime(clock.UtcNow.Date);
        var periods = repository.Query<AccountingPeriod>(tenantContext.TenantId)
            .Where(x => x.EndDate <= asOf)
            .OrderBy(x => x.EndDate)
            .ToList();
        if (periods.Count == 0)
        {
            return [];
        }

        var existingByPeriodId = repository.Query<InternalAuditCycle>(tenantContext.TenantId)
            .ToList()
            .ToDictionary(x => x.AccountingPeriodId, x => x);
        var created = new List<InternalAuditCycle>();
        var dueDays = Math.Max(0, policy.InternalAuditDueDaysAfterPeriodEnd);

        transaction.Execute(() =>
        {
            foreach (var period in periods)
            {
                if (existingByPeriodId.ContainsKey(period.Id))
                {
                    continue;
                }

                var cycle = new InternalAuditCycle
                {
                    TenantId = tenantContext.TenantId,
                    AccountingPeriodId = period.Id,
                    ReviewType = InternalAuditReviewType.InternalAudit,
                    PeriodStart = period.StartDate,
                    PeriodEnd = period.EndDate,
                    DueDate = period.EndDate.AddDays(dueDays),
                    Status = InternalAuditCycleStatus.Draft,
                    CreatedByUserId = tenantContext.UserId,
                    CreatedAtUtc = clock.UtcNow
                };
                repository.Add(cycle);
                created.Add(cycle);

                RecordEvent("InternalAuditCycle", cycle.Id, EventType.Create, null, Snapshot(cycle), "Generated periodic internal audit cycle.");
            }
        });

        return created;
    }

    public InternalAuditCycle CreateReviewPeriod(CreateInternalAuditCycleRequest request)
    {
        EnsureManagerOrComplianceOrAccountant();
        if (request.PeriodEnd < request.PeriodStart)
        {
            throw new DomainRuleException("Review period end must be on or after start.");
        }

        if (repository.Query<InternalAuditCycle>(tenantContext.TenantId)
            .Any(x => x.PeriodStart == request.PeriodStart && x.PeriodEnd == request.PeriodEnd && x.ReviewType == request.ReviewType))
        {
            throw new DomainRuleException("A review period for this range and type already exists.");
        }

        var policy = ResolvePolicy();
        var periodId = repository.Query<AccountingPeriod>(tenantContext.TenantId)
            .Where(x => x.StartDate == request.PeriodStart && x.EndDate == request.PeriodEnd)
            .Select(x => x.Id)
            .SingleOrDefault();

        var cycle = new InternalAuditCycle
        {
            TenantId = tenantContext.TenantId,
            AccountingPeriodId = periodId,
            ReviewType = request.ReviewType,
            PeriodStart = request.PeriodStart,
            PeriodEnd = request.PeriodEnd,
            DueDate = request.PeriodEnd.AddDays(Math.Max(0, policy.InternalAuditDueDaysAfterPeriodEnd)),
            Status = InternalAuditCycleStatus.Draft,
            CreatedByUserId = tenantContext.UserId,
            CreatedAtUtc = clock.UtcNow
        };

        repository.Add(cycle);
        RecordEvent("InternalAuditCycle", cycle.Id, EventType.Create, null, Snapshot(cycle), "Created compliance review period.");
        return cycle;
    }

    public IReadOnlyList<ComplianceReviewChecklistItem> AutoPopulateChecklistFromClauseMatrix(AutoPopulateInternalAuditChecklistRequest request)
    {
        EnsureManagerOrComplianceOrAccountant();
        var cycle = GetCycle(request.InternalAuditCycleId);
        if (cycle.Status != InternalAuditCycleStatus.Draft)
        {
            throw new DomainRuleException("Checklist auto-populate is only allowed while review is draft.");
        }

        var existing = repository.Query<ComplianceReviewChecklistItem>(tenantContext.TenantId)
            .Where(x => x.InternalAuditCycleId == cycle.Id)
            .ToList();
        if (existing.Count > 0)
        {
            return existing;
        }

        var created = new List<ComplianceReviewChecklistItem>();
        foreach (var (clauseRef, controlName) in ChecklistTemplate)
        {
            var item = new ComplianceReviewChecklistItem
            {
                TenantId = tenantContext.TenantId,
                InternalAuditCycleId = cycle.Id,
                ClauseRef = clauseRef,
                ControlName = controlName,
                UpdatedAtUtc = clock.UtcNow,
                UpdatedByUserId = tenantContext.UserId
            };
            repository.Add(item);
            created.Add(item);
        }

        RecordEvent("InternalAuditCycle", cycle.Id, EventType.UpdateDraft, null, new { CreatedChecklistItems = created.Count }, "Auto-populated compliance checklist.");
        return created;
    }

    public IReadOnlyList<InternalAuditCycleRow> Cycles(DateOnly? periodStart = null, DateOnly? periodEnd = null)
    {
        var query = repository.Query<InternalAuditCycle>(tenantContext.TenantId).AsQueryable();
        if (periodStart.HasValue)
        {
            query = query.Where(x => x.PeriodEnd >= periodStart.Value);
        }

        if (periodEnd.HasValue)
        {
            query = query.Where(x => x.PeriodStart <= periodEnd.Value);
        }

        var attestCountByCycle = repository.Query<InternalAuditAttestation>(tenantContext.TenantId)
            .ToList()
            .GroupBy(x => x.InternalAuditCycleId)
            .ToDictionary(x => x.Key, x => x.Count());
        var checklistByCycle = repository.Query<ComplianceReviewChecklistItem>(tenantContext.TenantId)
            .ToList()
            .GroupBy(x => x.InternalAuditCycleId)
            .ToDictionary(x => x.Key, x => x.ToList());

        return query
            .OrderByDescending(x => x.PeriodEnd)
            .ToList()
            .Select(x =>
            {
                var checklist = checklistByCycle.TryGetValue(x.Id, out var items) ? items : [];
                return new InternalAuditCycleRow(
                    x.Id,
                    x.AccountingPeriodId,
                    x.PeriodStart,
                    x.PeriodEnd,
                    x.DueDate,
                    x.Status.ToString(),
                    x.TieOutReviewCompleted,
                    x.UnallowableReviewCompleted,
                    x.BillingReviewCompleted,
                    x.MonthlyCloseReviewCompleted,
                    attestCountByCycle.TryGetValue(x.Id, out var count) ? count : 0,
                    x.SubmittedAtUtc,
                    x.CompletedAtUtc,
                    x.Summary,
                    x.Notes,
                    x.ReviewType.ToString(),
                    checklist.Count,
                    checklist.Count(i => i.Result.HasValue),
                    checklist.Count(i => i.Result == ComplianceChecklistResult.Fail),
                    x.ApprovedAtUtc,
                    x.ClosedAtUtc,
                    x.CreatedAtUtc);
            })
            .ToList();
    }

    public IReadOnlyList<InternalAuditAttestationRow> Attestations(Guid? internalAuditCycleId = null)
    {
        var query = repository.Query<InternalAuditAttestation>(tenantContext.TenantId).AsQueryable();
        if (internalAuditCycleId.HasValue)
        {
            query = query.Where(x => x.InternalAuditCycleId == internalAuditCycleId.Value);
        }

        return query
            .OrderByDescending(x => x.AttestedAtUtc)
            .ToList()
            .Select(x => new InternalAuditAttestationRow(
                x.InternalAuditCycleId,
                x.Id,
                x.AttestationType.ToString(),
                x.AttestedByUserId,
                x.AttestedByRoles,
                x.AttestedAtUtc,
                x.Statement,
                x.Notes))
            .ToList();
    }

    public IReadOnlyList<ComplianceReviewChecklistRow> Checklist(Guid? internalAuditCycleId = null)
    {
        var query = repository.Query<ComplianceReviewChecklistItem>(tenantContext.TenantId);
        if (internalAuditCycleId.HasValue)
        {
            query = query.Where(x => x.InternalAuditCycleId == internalAuditCycleId.Value);
        }

        return query.OrderBy(x => x.ClauseRef).ThenBy(x => x.ControlName).ToList().Select(x => new ComplianceReviewChecklistRow(
            x.InternalAuditCycleId,
            x.Id,
            x.ClauseRef,
            x.ControlName,
            x.Result?.ToString() ?? string.Empty,
            x.Notes,
            x.UpdatedAtUtc,
            x.UpdatedByUserId)).ToList();
    }

    public IReadOnlyList<ComplianceExceptionRow> Exceptions(Guid? internalAuditCycleId = null)
    {
        var query = repository.Query<ComplianceException>(tenantContext.TenantId);
        if (internalAuditCycleId.HasValue)
        {
            query = query.Where(x => x.InternalAuditCycleId == internalAuditCycleId.Value);
        }

        return query.OrderByDescending(x => x.DueDate).ToList().Select(x => new ComplianceExceptionRow(
            x.InternalAuditCycleId,
            x.Id,
            x.ChecklistItemId,
            x.Severity.ToString(),
            x.Category.ToString(),
            x.Description,
            x.RootCause,
            x.RemediationPlan,
            x.OwnerUserId,
            x.DueDate,
            x.Status.ToString(),
            x.ResolvedAtUtc,
            x.ResolvedByUserId,
            x.ResolutionNotes)).ToList();
    }

    public InternalAuditCycle UpsertChecklist(UpsertInternalAuditChecklistRequest request)
    {
        EnsureManagerOrComplianceOrAccountant();
        var cycle = GetCycle(request.InternalAuditCycleId);
        if (cycle.Status == InternalAuditCycleStatus.Completed || cycle.Status == InternalAuditCycleStatus.Closed)
        {
            throw new DomainRuleException("Completed/closed internal audit cycles are immutable.");
        }

        var before = Snapshot(cycle);
        cycle.TieOutReviewCompleted = request.TieOutReviewCompleted;
        cycle.UnallowableReviewCompleted = request.UnallowableReviewCompleted;
        cycle.BillingReviewCompleted = request.BillingReviewCompleted;
        cycle.MonthlyCloseReviewCompleted = request.MonthlyCloseReviewCompleted;
        cycle.Notes = NormalizeOptional(request.Notes);

        repository.Update(cycle);
        RecordEvent("InternalAuditCycle", cycle.Id, EventType.UpdateDraft, before, Snapshot(cycle), "Updated internal audit checklist.");
        EnsureChecklistSeeded(cycle);
        SyncLegacyChecklistFlagsToItems(cycle, request, tenantContext.UserId);
        return cycle;
    }

    public ComplianceReviewChecklistItem UpsertChecklistItem(UpsertInternalAuditChecklistItemRequest request)
    {
        EnsureManagerOrComplianceOrAccountant();
        var cycle = GetCycle(request.InternalAuditCycleId);
        if (cycle.Status == InternalAuditCycleStatus.Closed || cycle.Status == InternalAuditCycleStatus.Completed)
        {
            throw new DomainRuleException("Cannot edit checklist items for completed/closed reviews.");
        }

        var item = repository.Query<ComplianceReviewChecklistItem>(tenantContext.TenantId)
            .SingleOrDefault(x => x.Id == request.ChecklistItemId && x.InternalAuditCycleId == cycle.Id)
            ?? throw new DomainRuleException("Checklist item not found.");
        var before = new { item.Result, item.Notes };
        item.Result = request.Result;
        item.Notes = NormalizeOptional(request.Notes);
        item.UpdatedAtUtc = clock.UtcNow;
        item.UpdatedByUserId = tenantContext.UserId;
        repository.Update(item);
        RecordEvent("ComplianceReviewChecklistItem", item.Id, EventType.UpdateDraft, before, item, "Updated compliance checklist item.");

        if (item.Result == ComplianceChecklistResult.Fail)
        {
            _ = OpenExceptionFromFailedChecklistItem(cycle, item);
        }

        return item;
    }

    public InternalAuditCycle SubmitForAttestation(SubmitInternalAuditCycleRequest request)
    {
        EnsureManagerOrComplianceOrAccountant();
        var cycle = GetCycle(request.InternalAuditCycleId);
        if (cycle.Status != InternalAuditCycleStatus.Draft)
        {
            throw new DomainRuleException("Only draft internal audit cycles can be submitted.");
        }

        if (!EffectiveChecklistComplete(cycle))
        {
            throw new DomainRuleException("All internal audit checklist steps must be completed before submission.");
        }

        var summary = NormalizeRequired(request.Summary, "Internal audit summary is required.");
        var before = Snapshot(cycle);
        cycle.Status = InternalAuditCycleStatus.PendingAttestation;
        cycle.SubmittedAtUtc = clock.UtcNow;
        cycle.SubmittedByUserId = tenantContext.UserId;
        cycle.Summary = summary;
        repository.Update(cycle);
        RecordEvent("InternalAuditCycle", cycle.Id, EventType.Submit, before, Snapshot(cycle), "Submitted internal audit cycle for attestation.");

        foreach (var role in RequiredAttestationRoles(ResolvePolicy()))
        {
            notifications.SendToRole(
                role,
                "Internal Audit Attestation Required",
                $"Internal audit cycle {cycle.Id} for period {cycle.PeriodStart:yyyy-MM-dd} to {cycle.PeriodEnd:yyyy-MM-dd} is pending attestation.",
                "InternalAudit");
        }

        return cycle;
    }

    public InternalAuditAttestation RecordAttestation(RecordInternalAuditAttestationRequest request)
    {
        var cycle = GetCycle(request.InternalAuditCycleId);
        if (cycle.Status != InternalAuditCycleStatus.PendingAttestation && cycle.Status != InternalAuditCycleStatus.Submitted)
        {
            throw new DomainRuleException("Internal audit cycle must be pending attestation or submitted.");
        }

        EnsureAttestationRole(request.AttestationType);
        var statement = NormalizeRequired(request.Statement, "Attestation statement is required.");
        var existing = repository.Query<InternalAuditAttestation>(tenantContext.TenantId)
            .SingleOrDefault(x => x.InternalAuditCycleId == cycle.Id && x.AttestationType == request.AttestationType);
        if (existing is not null)
        {
            throw new DomainRuleException($"Attestation already recorded for {request.AttestationType}.");
        }

        var attestation = new InternalAuditAttestation
        {
            TenantId = tenantContext.TenantId,
            InternalAuditCycleId = cycle.Id,
            AttestationType = request.AttestationType,
            AttestedByUserId = tenantContext.UserId,
            AttestedByRoles = string.Join(',', tenantContext.Roles),
            AttestedAtUtc = clock.UtcNow,
            Statement = statement,
            Notes = NormalizeOptional(request.Notes)
        };
        repository.Add(attestation);
        RecordEvent("InternalAuditAttestation", attestation.Id, EventType.InternalAuditAttestation, null, attestation, $"Recorded {request.AttestationType} attestation.");
        return attestation;
    }

    public InternalAuditCycle SubmitReview(SubmitInternalAuditCycleRequest request)
    {
        EnsureManagerOrComplianceOrAccountant();
        var cycle = GetCycle(request.InternalAuditCycleId);
        if (cycle.Status != InternalAuditCycleStatus.PendingAttestation && cycle.Status != InternalAuditCycleStatus.Draft)
        {
            throw new DomainRuleException("Only draft or pending-attestation reviews can be submitted.");
        }

        EnsureChecklistSeeded(cycle);
        var checklist = repository.Query<ComplianceReviewChecklistItem>(tenantContext.TenantId)
            .Where(x => x.InternalAuditCycleId == cycle.Id)
            .ToList();
        if (checklist.Count == 0 || checklist.Any(x => !x.Result.HasValue))
        {
            throw new DomainRuleException("All checklist items must have a result before submit.");
        }

        var attestationCount = repository.Query<InternalAuditAttestation>(tenantContext.TenantId)
            .Count(x => x.InternalAuditCycleId == cycle.Id);
        if (attestationCount < 1)
        {
            throw new DomainRuleException("At least one attestation is required before submit.");
        }

        _ = OpenExceptionsFromFailedChecklistItems(cycle.Id);

        var before = Snapshot(cycle);
        cycle.Status = InternalAuditCycleStatus.Submitted;
        cycle.SubmittedAtUtc = clock.UtcNow;
        cycle.SubmittedByUserId = tenantContext.UserId;
        cycle.Summary = NormalizeRequired(request.Summary, "Review summary is required.");
        repository.Update(cycle);
        RecordEvent("InternalAuditCycle", cycle.Id, EventType.Submit, before, Snapshot(cycle), "Submitted review for manager approval.");
        notifications.SendToRole("Manager", "Compliance Review Pending Approval", $"Review {cycle.Id} is ready for manager approval.", "InternalAudit");
        return cycle;
    }

    public InternalAuditCycle ApproveReview(ApproveInternalAuditCycleRequest request)
    {
        EnsureManager();
        var cycle = GetCycle(request.InternalAuditCycleId);
        if (cycle.Status != InternalAuditCycleStatus.Submitted)
        {
            throw new DomainRuleException("Only submitted reviews can be approved.");
        }

        if (cycle.SubmittedByUserId.HasValue && cycle.SubmittedByUserId.Value == tenantContext.UserId)
        {
            throw new DomainRuleException("Approver cannot be submitter (maker-checker).");
        }

        var before = Snapshot(cycle);
        cycle.Status = InternalAuditCycleStatus.Approved;
        cycle.ApprovedAtUtc = clock.UtcNow;
        cycle.ApprovedByUserId = tenantContext.UserId;
        if (!string.IsNullOrWhiteSpace(request.ApprovalNotes))
        {
            cycle.Notes = AppendNotes(cycle.Notes, $"[Approval] {request.ApprovalNotes.Trim()}");
        }

        repository.Update(cycle);
        RecordEvent("InternalAuditCycle", cycle.Id, EventType.Approve, before, Snapshot(cycle), "Approved review.");
        return cycle;
    }

    public InternalAuditCycle CloseReview(CompleteInternalAuditCycleRequest request)
    {
        EnsureManager();
        var cycle = GetCycle(request.InternalAuditCycleId);
        if (cycle.Status != InternalAuditCycleStatus.Approved)
        {
            throw new DomainRuleException("Only approved reviews can be closed.");
        }

        var hasOpenExceptions = repository.Query<ComplianceException>(tenantContext.TenantId)
            .Any(x => x.InternalAuditCycleId == cycle.Id && x.Status == ComplianceExceptionStatus.Open);
        if (hasOpenExceptions)
        {
            throw new DomainRuleException("Cannot close review while open exceptions exist.");
        }

        var before = Snapshot(cycle);
        cycle.Status = InternalAuditCycleStatus.Closed;
        cycle.ClosedAtUtc = clock.UtcNow;
        cycle.ClosedByUserId = tenantContext.UserId;
        if (!string.IsNullOrWhiteSpace(request.Notes))
        {
            cycle.Notes = AppendNotes(cycle.Notes, $"[Close] {request.Notes.Trim()}");
        }

        repository.Update(cycle);
        RecordEvent("InternalAuditCycle", cycle.Id, EventType.Approve, before, Snapshot(cycle), "Closed review.");
        return cycle;
    }

    public IReadOnlyList<ComplianceException> OpenExceptionsFromFailedChecklistItems(Guid internalAuditCycleId)
    {
        EnsureManagerOrComplianceOrAccountant();
        var cycle = GetCycle(internalAuditCycleId);
        var failedItems = repository.Query<ComplianceReviewChecklistItem>(tenantContext.TenantId)
            .Where(x => x.InternalAuditCycleId == cycle.Id && x.Result == ComplianceChecklistResult.Fail)
            .ToList();
        var created = new List<ComplianceException>();
        foreach (var item in failedItems)
        {
            created.Add(OpenExceptionFromFailedChecklistItem(cycle, item));
        }

        return created.GroupBy(x => x.Id).Select(x => x.First()).ToList();
    }

    public ComplianceException ResolveException(ResolveComplianceExceptionRequest request)
    {
        EnsureManagerOrComplianceOrAccountant();
        var exception = GetException(request.ComplianceExceptionId);
        if (exception.Status != ComplianceExceptionStatus.Open)
        {
            throw new DomainRuleException("Only open exceptions can be resolved.");
        }

        var before = Snapshot(exception);
        exception.Status = ComplianceExceptionStatus.Resolved;
        exception.ResolvedAtUtc = clock.UtcNow;
        exception.ResolvedByUserId = tenantContext.UserId;
        exception.ResolutionNotes = NormalizeRequired(request.ResolutionNotes, "Resolution notes are required.");
        repository.Update(exception);
        RecordEvent("ComplianceException", exception.Id, EventType.ComplianceExceptionChange, before, Snapshot(exception), "Resolved compliance exception.");
        return exception;
    }

    public ComplianceException AcceptRisk(AcceptComplianceRiskRequest request)
    {
        EnsureManager();
        var exception = GetException(request.ComplianceExceptionId);
        if (exception.Status != ComplianceExceptionStatus.Open)
        {
            throw new DomainRuleException("Only open exceptions can be accepted as risk.");
        }

        var before = Snapshot(exception);
        exception.Status = ComplianceExceptionStatus.AcceptedRisk;
        exception.ResolvedAtUtc = clock.UtcNow;
        exception.ResolvedByUserId = tenantContext.UserId;
        exception.ResolutionNotes = NormalizeRequired(request.ResolutionNotes, "Risk acceptance notes are required.");
        repository.Update(exception);
        RecordEvent("ComplianceException", exception.Id, EventType.ComplianceExceptionChange, before, Snapshot(exception), "Accepted risk.");
        return exception;
    }

    public InternalAuditCycle AddResolutionNote(AddInternalAuditResolutionNoteRequest request)
    {
        EnsureManagerOrComplianceOrAccountant();
        var cycle = GetCycle(request.InternalAuditCycleId);
        if (cycle.Status != InternalAuditCycleStatus.Approved && cycle.Status != InternalAuditCycleStatus.Closed)
        {
            throw new DomainRuleException("Resolution notes are only allowed on approved/closed reviews.");
        }

        var before = Snapshot(cycle);
        cycle.Notes = AppendNotes(cycle.Notes, NormalizeRequired(request.ResolutionNote, "Resolution note is required."));
        repository.Update(cycle);
        RecordEvent("InternalAuditCycle", cycle.Id, EventType.UpdateDraft, before, Snapshot(cycle), "Added resolution note.");
        return cycle;
    }

    public InternalAuditCycle CompleteCycle(CompleteInternalAuditCycleRequest request)
    {
        EnsureManager();
        var cycle = GetCycle(request.InternalAuditCycleId);
        if (cycle.Status == InternalAuditCycleStatus.Approved)
        {
            return CloseReview(request);
        }

        if (cycle.Status != InternalAuditCycleStatus.PendingAttestation)
        {
            throw new DomainRuleException("Only pending-attestation or approved cycles can be completed.");
        }

        var requiredTypes = RequiredAttestationTypes(ResolvePolicy()).ToHashSet();
        var receivedTypes = repository.Query<InternalAuditAttestation>(tenantContext.TenantId)
            .Where(x => x.InternalAuditCycleId == cycle.Id)
            .Select(x => x.AttestationType)
            .Distinct()
            .ToHashSet();
        if (requiredTypes.Any(x => !receivedTypes.Contains(x)))
        {
            throw new DomainRuleException("Required attestations are incomplete.");
        }

        var before = Snapshot(cycle);
        cycle.Status = InternalAuditCycleStatus.Completed;
        cycle.CompletedAtUtc = clock.UtcNow;
        cycle.CompletedByUserId = tenantContext.UserId;
        cycle.Notes = string.IsNullOrWhiteSpace(request.Notes)
            ? cycle.Notes
            : request.Notes.Trim();
        repository.Update(cycle);
        RecordEvent("InternalAuditCycle", cycle.Id, EventType.Approve, before, Snapshot(cycle), "Completed internal audit cycle.");
        return cycle;
    }

    public IReadOnlyList<InternalAuditComplianceRow> ComplianceReport(DateOnly? asOfDate = null)
    {
        var asOf = asOfDate ?? DateOnly.FromDateTime(clock.UtcNow.Date);
        _ = SyncCycles(asOf);
        var requiredAttestationCount = RequiredAttestationTypes(ResolvePolicy()).Count();
        var attestationsByCycle = repository.Query<InternalAuditAttestation>(tenantContext.TenantId)
            .ToList()
            .GroupBy(x => x.InternalAuditCycleId)
            .ToDictionary(x => x.Key, x => x.Select(v => v.AttestationType).Distinct().Count());
        var checklistByCycle = repository.Query<ComplianceReviewChecklistItem>(tenantContext.TenantId)
            .ToList()
            .GroupBy(x => x.InternalAuditCycleId)
            .ToDictionary(x => x.Key, x => x.ToList());
        var openExceptionsByCycle = repository.Query<ComplianceException>(tenantContext.TenantId)
            .Where(x => x.Status == ComplianceExceptionStatus.Open)
            .ToList()
            .GroupBy(x => x.InternalAuditCycleId)
            .ToDictionary(x => x.Key, x => x.Count());

        return repository.Query<InternalAuditCycle>(tenantContext.TenantId)
            .OrderByDescending(x => x.PeriodEnd)
            .ToList()
            .Select(x =>
            {
                var daysPastDue = asOf > x.DueDate ? asOf.DayNumber - x.DueDate.DayNumber : 0;
                var received = attestationsByCycle.TryGetValue(x.Id, out var count) ? count : 0;
                var checklist = checklistByCycle.TryGetValue(x.Id, out var items) ? items : [];
                var checklistComplete = checklist.Count > 0 ? checklist.All(i => i.Result.HasValue) : ChecklistComplete(x);
                var openExceptions = openExceptionsByCycle.TryGetValue(x.Id, out var openCount) ? openCount : 0;
                return new InternalAuditComplianceRow(
                    x.Id,
                    x.PeriodStart,
                    x.PeriodEnd,
                    x.DueDate,
                    x.Status.ToString(),
                    daysPastDue,
                    x.Status != InternalAuditCycleStatus.Completed && x.Status != InternalAuditCycleStatus.Closed && asOf > x.DueDate,
                    requiredAttestationCount,
                    received,
                    checklistComplete,
                    openExceptions);
            })
            .ToList();
    }

    private InternalAuditCycle GetCycle(Guid cycleId)
    {
        return repository.Query<InternalAuditCycle>(tenantContext.TenantId).SingleOrDefault(x => x.Id == cycleId)
            ?? throw new DomainRuleException("Internal audit cycle not found.");
    }

    private ComplianceException GetException(Guid exceptionId)
    {
        return repository.Query<ComplianceException>(tenantContext.TenantId).SingleOrDefault(x => x.Id == exceptionId)
            ?? throw new DomainRuleException("Compliance exception not found.");
    }

    private ManagementReviewPolicy ResolvePolicy()
    {
        return repository.Query<ManagementReviewPolicy>(tenantContext.TenantId).SingleOrDefault()
            ?? new ManagementReviewPolicy
            {
                TenantId = tenantContext.TenantId,
                EnablePeriodicInternalAuditAttestation = true,
                InternalAuditCadenceDays = 30,
                InternalAuditDueDaysAfterPeriodEnd = 10,
                RequireManagerInternalAuditAttestation = true,
                RequireComplianceInternalAuditAttestation = true
            };
    }

    private IEnumerable<InternalAuditAttestationType> RequiredAttestationTypes(ManagementReviewPolicy policy)
    {
        if (policy.RequireManagerInternalAuditAttestation)
        {
            yield return InternalAuditAttestationType.Manager;
        }

        if (policy.RequireComplianceInternalAuditAttestation)
        {
            yield return InternalAuditAttestationType.Compliance;
        }
    }

    private IEnumerable<string> RequiredAttestationRoles(ManagementReviewPolicy policy)
    {
        if (policy.RequireManagerInternalAuditAttestation)
        {
            yield return "Manager";
        }

        if (policy.RequireComplianceInternalAuditAttestation)
        {
            yield return "Compliance";
        }
    }

    private static bool ChecklistComplete(InternalAuditCycle cycle)
    {
        return cycle.TieOutReviewCompleted
               && cycle.UnallowableReviewCompleted
               && cycle.BillingReviewCompleted
               && cycle.MonthlyCloseReviewCompleted;
    }

    private bool EffectiveChecklistComplete(InternalAuditCycle cycle)
    {
        var checklist = repository.Query<ComplianceReviewChecklistItem>(tenantContext.TenantId)
            .Where(x => x.InternalAuditCycleId == cycle.Id)
            .ToList();
        if (ChecklistComplete(cycle))
        {
            return true;
        }

        if (checklist.Count == 0)
        {
            return ChecklistComplete(cycle);
        }

        return checklist.All(x => x.Result.HasValue);
    }

    private void EnsureChecklistSeeded(InternalAuditCycle cycle)
    {
        var hasChecklist = repository.Query<ComplianceReviewChecklistItem>(tenantContext.TenantId)
            .Any(x => x.InternalAuditCycleId == cycle.Id);
        if (!hasChecklist)
        {
            _ = AutoPopulateChecklistFromClauseMatrix(new AutoPopulateInternalAuditChecklistRequest(cycle.Id));
        }
    }

    private void SyncLegacyChecklistFlagsToItems(InternalAuditCycle cycle, UpsertInternalAuditChecklistRequest request, Guid actorUserId)
    {
        var items = repository.Query<ComplianceReviewChecklistItem>(tenantContext.TenantId)
            .Where(x => x.InternalAuditCycleId == cycle.Id)
            .ToList();

        SetChecklistResult(items, "(c)(6)", request.TieOutReviewCompleted, actorUserId);
        SetChecklistResult(items, "(c)(12)", request.UnallowableReviewCompleted, actorUserId);
        SetChecklistResult(items, "(c)(16)", request.BillingReviewCompleted, actorUserId);
        SetChecklistResult(items, "(c)(11)", request.MonthlyCloseReviewCompleted, actorUserId);
    }

    private void SetChecklistResult(
        IReadOnlyList<ComplianceReviewChecklistItem> items,
        string clauseRef,
        bool completed,
        Guid actorUserId)
    {
        var item = items.FirstOrDefault(x => string.Equals(x.ClauseRef, clauseRef, StringComparison.OrdinalIgnoreCase));
        if (item is null)
        {
            return;
        }

        item.Result = completed ? ComplianceChecklistResult.Pass : null;
        item.UpdatedAtUtc = clock.UtcNow;
        item.UpdatedByUserId = actorUserId;
        repository.Update(item);
    }

    private ComplianceException OpenExceptionFromFailedChecklistItem(InternalAuditCycle cycle, ComplianceReviewChecklistItem item)
    {
        var existing = repository.Query<ComplianceException>(tenantContext.TenantId)
            .SingleOrDefault(x => x.InternalAuditCycleId == cycle.Id
                                  && x.ChecklistItemId == item.Id
                                  && x.Status == ComplianceExceptionStatus.Open);
        if (existing is not null)
        {
            return existing;
        }

        var exception = new ComplianceException
        {
            TenantId = tenantContext.TenantId,
            InternalAuditCycleId = cycle.Id,
            ChecklistItemId = item.Id,
            Severity = ComplianceExceptionSeverity.Medium,
            Category = MapExceptionCategory(item.ClauseRef),
            Description = $"Checklist item failed: {item.ClauseRef} {item.ControlName}",
            RootCause = item.Notes,
            RemediationPlan = "Document corrective action and re-test control operation.",
            OwnerUserId = cycle.CreatedByUserId,
            DueDate = cycle.DueDate,
            Status = ComplianceExceptionStatus.Open
        };

        repository.Add(exception);
        RecordEvent("ComplianceException", exception.Id, EventType.ComplianceExceptionChange, null, Snapshot(exception), "Opened exception from failed checklist item.");
        return exception;
    }

    private static ComplianceExceptionCategory MapExceptionCategory(string clauseRef)
    {
        return clauseRef switch
        {
            "(c)(9)" => ComplianceExceptionCategory.Timesheet,
            "(c)(11)" => ComplianceExceptionCategory.Close,
            "(c)(12)" => ComplianceExceptionCategory.Indirect,
            "(c)(16)" => ComplianceExceptionCategory.Billing,
            "(c)(6)" => ComplianceExceptionCategory.Reconciliation,
            "(c)(7)" => ComplianceExceptionCategory.JE,
            _ => ComplianceExceptionCategory.Reconciliation
        };
    }

    private void EnsureAttestationRole(InternalAuditAttestationType type)
    {
        if (type == InternalAuditAttestationType.Manager)
        {
            EnsureManager();
            return;
        }

        if (tenantContext.Roles.Contains("Compliance", StringComparer.OrdinalIgnoreCase))
        {
            return;
        }

        throw new DomainRuleException("Only compliance can submit compliance attestations.");
    }

    private void EnsureManager()
    {
        if (tenantContext.Roles.Contains("Manager", StringComparer.OrdinalIgnoreCase))
        {
            return;
        }

        throw new DomainRuleException("Only managers can perform this action.");
    }

    private void EnsureManagerOrComplianceOrAccountant()
    {
        if (tenantContext.Roles.Contains("Manager", StringComparer.OrdinalIgnoreCase)
            || tenantContext.Roles.Contains("Compliance", StringComparer.OrdinalIgnoreCase)
            || tenantContext.Roles.Contains("Accountant", StringComparer.OrdinalIgnoreCase))
        {
            return;
        }

        throw new DomainRuleException("Only manager, compliance, or accountant roles can perform this action.");
    }

    private static string NormalizeRequired(string? value, string message)
    {
        var normalized = value?.Trim();
        if (string.IsNullOrWhiteSpace(normalized))
        {
            throw new DomainRuleException(message);
        }

        return normalized;
    }

    private static string? NormalizeOptional(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }

    private static string AppendNotes(string? existing, string additional)
    {
        if (string.IsNullOrWhiteSpace(existing))
        {
            return additional;
        }

        return $"{existing}{Environment.NewLine}{additional}";
    }

    private object Snapshot(InternalAuditCycle cycle)
    {
        return new
        {
            cycle.Id,
            cycle.AccountingPeriodId,
            cycle.PeriodStart,
            cycle.PeriodEnd,
            cycle.DueDate,
            cycle.Status,
            cycle.ReviewType,
            cycle.TieOutReviewCompleted,
            cycle.UnallowableReviewCompleted,
            cycle.BillingReviewCompleted,
            cycle.MonthlyCloseReviewCompleted,
            cycle.CreatedByUserId,
            cycle.CreatedAtUtc,
            cycle.SubmittedAtUtc,
            cycle.SubmittedByUserId,
            cycle.ApprovedAtUtc,
            cycle.ApprovedByUserId,
            cycle.CompletedAtUtc,
            cycle.CompletedByUserId,
            cycle.ClosedAtUtc,
            cycle.ClosedByUserId,
            cycle.Summary,
            cycle.Notes
        };
    }

    private static object Snapshot(ComplianceException exception)
    {
        return new
        {
            exception.Id,
            exception.InternalAuditCycleId,
            exception.ChecklistItemId,
            exception.Severity,
            exception.Category,
            exception.Description,
            exception.RootCause,
            exception.RemediationPlan,
            exception.OwnerUserId,
            exception.DueDate,
            exception.Status,
            exception.ResolvedAtUtc,
            exception.ResolvedByUserId,
            exception.ResolutionNotes
        };
    }

    private void RecordEvent(string entityType, Guid entityId, EventType eventType, object? before, object? after, string? reason)
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
